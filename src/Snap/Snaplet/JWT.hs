{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

{-|

This snaplet provides a framework for using <https://jwt.io/ JSON Web Tokens>
(or JWTs) in a <http://snapframework.com/ Snap> application. It is based on the
excellent <http://hackage.haskell.org/package/jose jose> package by Fraser
Tweedale.

To get started, first include this snaplet in your application's state.

> data App = App
>     {
>     , ...
>     , _jwt :: Snaplet JWTState
>     }

Next, call the jwtInit from your application's initializer.

> appInit = makeSnaplet ... $ do
>     ...
>     j <- nestSnaplet "jwt" jwt jwtInit
>     return $ App ... j

Now any of the JWT functions defined in this module can be used in your
application handlers.

> tokenHandler :: Handler App App ()
> tokenHandler = do
>     ...
>     token <- with jwt $ issueToken "userID"
>     ...

You can eliminate some of the boilerplate by defining a
'Snap.Snaplet.JWT.HasJWTState' instance for your application.

> instance HasJWTState (Handler App App) where
>   getJWTState = with jwt $ get
>   putJWTState = with jwt . put

Using this instance, tokenHandler no longer requires the 'Snap.Snaplet.with' function.

> tokenHandler :: Handler App App ()
> tokenHandler = do
>     ...
>     token <- issueToken "userID"
>     ...

The first time you run an application with jwt-snaplet a configuration file
@devel.cfg@ is created in the @snaplets/jwt@ directory under your project root.
The configuration values supported are:

[@issuer@] A string that identifies the token issuer. This is used to specify
the issuer claim in claimsets created by 'Snap.Snaplet.JWT.defaultClaimsSet'.

[@clock_skew@] The number of seconds of clock skew to allow when validating not
before and expiration time claims.

[@token_ttl@] The number of seconds newly created tokens should be valid for.
The expiration time claim in claimsets created by
'Snap.Snaplet.JWT.defaultClaimsSet' is set to the current time plus this many
seconds.

[@header_path@] The full path to a file that contains a valid JSON
representation of a JSON Web Signature header. This header will be used to
create all new tokens.

[@active_key_dir@] The full path to a directory of files that each contain a
valid JSON representation of a JSON Web Key (JWK). These keys will be used to
validate tokens. Tokens are valid if any key in this set can be used to
validate the token signature. This allows signing keys to be rotated without
invalidating all currently issued tokens as long as the signing key is
maintained as part of the active key set for at least as long as the token TTL
plus the allowed clock skew.

[@signing_key_path@] The full path to a file that contains a valid JSON
representation of a JSON Web Key (JWK). This key will be used to sign all new
tokens.

-}
module Snap.Snaplet.JWT (
    -- * The Snaplet
    JWTState,
    HasJWTState,
    withJWTState,
    getJWTState,
    putJWTState,
    Error,
    jwtInit,
    defaultClaimsSet,
    createJWSJWT',
    validateJWSJWT',
    validateClaimsSet,
    validateClaimsSet',
    getValidatedClaimsSet,
    issueToken,
    parseToken,
    -- * Re-exports
    module Crypto.JWT,
) where

import           Control.Lens          (set, (^.))
import           Control.Lens.TH       (makeLenses)
import           Control.Monad         (filterM)
import           Control.Monad.State   (get, put)
import           Control.Monad.Trans   (MonadIO, liftIO)
import           Crypto.JOSE.Compact   (decodeCompact, encodeCompact)
import qualified Crypto.JOSE.Error
import           Crypto.JOSE.JWK       (JWK, jwkKid)
import           Crypto.JOSE.JWS       (JWSHeader)
import           Crypto.JWT
import           Crypto.Random         (SystemDRG, getSystemDRG, withDRG)
import           Data.Aeson            (FromJSON, decodeStrict)
import           Data.ByteString.Lazy  (ByteString)
import qualified Data.Configurator     as Config
import           Data.Default.Class    (def)
import           Data.Either           (lefts)
import qualified Data.HashMap.Strict   as Map
import qualified Data.List             as List
import           Data.Maybe            (catMaybes, fromMaybe)
import qualified Data.Text             as T
import           Data.Text.Encoding    (encodeUtf8)
import qualified Data.Text.IO          as T
import           Data.Time.Clock       (NominalDiffTime, UTCTime (..),
                                        addUTCTime, getCurrentTime)
import qualified Data.UUID             as UUID
import qualified Data.UUID.V4          as UUID
import           Snap.Snaplet          (Handler, Initializer, SnapletInit,
                                        getSnapletUserConfig, makeSnaplet,
                                        printInfo)
import           System.Directory      (doesFileExist, getDirectoryContents)
import           System.FilePath.Posix ((</>))
import           Text.Printf           (printf)

import           Paths_snaplet_jwt

instance Ord NumericDate where
    compare (NumericDate t1) (NumericDate t2) = compare t1 t2

-- | The state for the JWT snaplet. Include this in your application state and
-- use 'Snap.Snaplet.JWT.jwtInit' to initialize it.
data JWTState = JWTState
    { _header     :: JWSHeader       -- ^ JSON Web Signature header used for creating JWTs
    , _keys       :: [JWK]           -- ^ Set of allowed JSON Web Keys used for validating tokens
    , _signingKey :: JWK             -- ^ JSON Web Key used for signing tokens
    , _issuer     :: T.Text          -- ^ String used for default issuer claims
    , _clockSkew  :: NominalDiffTime -- ^ Clock skew allowed when validating token claims
    , _tokenTTL   :: NominalDiffTime -- ^ Time to live used for default not before claims
    , _rng        :: SystemDRG       -- ^ System entropy pool used for default ID claims
    }

makeLenses ''JWTState

-- | Instantiate this typeclass on \"Handler b YourAppState\" so this snaplet
-- can find and update the JWT state. If you need to have multiple instances of
-- the JWT snaplet in your application, then don't provide this instance and
-- leverage the default instance using 'Snap.Snaplet.with'.
class HasJWTState b where
    getJWTState :: b JWTState
    putJWTState :: JWTState -> b ()

-- | Default instance of 'Snap.Snaplet.JWT.HasJWTState'
instance HasJWTState (Handler b JWTState) where
    getJWTState = get
    putJWTState = put

-- | Convenience function for executing a function using the default instance
-- of 'Snap.Snaplet.JWT.HasJWTState'.
withJWTState :: (HasJWTState m, MonadIO m) => (JWTState -> m b) -> m b
withJWTState = (getJWTState >>=)

-- | An extended version of 'Crypto.JOSE.Error.Error' that adds cases for
-- invalid signatures and claims.
data Error
    = JWTError Crypto.JOSE.Error.Error
    | InvalidSignature
    | InvalidClaimsSet String
    deriving (Eq, Show)

-- | Initialize the Snaplet.
jwtInit :: SnapletInit b JWTState
jwtInit = makeSnaplet "jwt" "JSON Web Tokens" (Just getDataDir) $ do
    config <- getSnapletUserConfig
    JWTState <$> loadHeader
             <*> loadKeys
             <*> loadSigningKey
             <*> liftIO (Config.require config "issuer")
             <*> liftIO (fromInteger <$> Config.require config "clock_skew")
             <*> liftIO (fromInteger <$> Config.require config "token_ttl")
             <*> liftIO getSystemDRG

-- | Load the JWT header in the context of the snaplet initializer.
loadHeader :: Initializer b v JWSHeader
loadHeader = do
    config <- getSnapletUserConfig
    path <- liftIO $ Config.require config "header_path"
    jwsHeader <- liftIO $ decodeFile path
    printInfo $ T.pack $ printf "... loaded header from %v" path
    return jwsHeader

-- | Load all active keys in the context of the snaplet initializer.
loadKeys :: Initializer b v [JWK]
loadKeys = do
    config <- getSnapletUserConfig
    path <- liftIO $ Config.require config "active_key_dir"
    jwks <- liftIO $ decodeDir path
    printInfo $ T.pack $ printf "... loaded %v active keys from %v" (length jwks) path
    printInfo $ T.pack $ printf "... active key ids: %v" (List.intercalate "," $ catMaybes $ map (^. jwkKid) jwks)
    return jwks

-- | Load the signing key in the context of the snaplet initializer.
loadSigningKey :: Initializer b v JWK
loadSigningKey = do
    config <- getSnapletUserConfig
    path <- liftIO $ Config.require config "signing_key_path"
    jwk <- liftIO $ decodeFile path
    printInfo $ T.pack $ printf "... loaded signing key from %v" path
    printInfo $ T.pack $ printf "... signing key id: %v" (fromMaybe "" $ jwk ^. jwkKid)
    return jwk

-- | Decode JSON objects from each file in a given directory.
decodeDir :: FromJSON a
          => FilePath -- ^ Path to directory
          -> IO [a]   -- ^ Returns an array of JSON objects
decodeDir dir = do
    dirContents <- getDirectoryContents dir
    files <- filterM (\f -> doesFileExist $ dir </> f) dirContents
    mapM (\f -> decodeFile $ dir </> f) files

-- | Decode a JSON object from the file at a given path.
decodeFile :: FromJSON a
           => FilePath -- ^ Path to file
           -> IO a     -- ^ Returns a JSON object
decodeFile file = do
    txt <- T.readFile file
    case decodeStrict . encodeUtf8 . T.strip $ txt of
        Just a -> return a
        Nothing -> error $ "failed to decode json: " ++ T.unpack txt

-- | Construct a default 'Crypto.JWT.ClaimSet' from parameters, Snaplet state,
-- current time, and a random UUID. The default claim set makes the following
-- claims: issuer, subject, expiration time, not before time, issued at time,
-- and ID.
defaultClaimsSet :: (HasJWTState m, MonadIO m)
                 => T.Text       -- ^ ClaimSet subject
                 -> m ClaimsSet  -- ^ Return a ClaimSet
defaultClaimsSet sub = withJWTState $ \state -> do
    now <- liftIO getCurrentTime
    uuid <- liftIO UUID.nextRandom
    let iss  = Just $ fromString $ state ^. issuer
        sub' = Just $ fromString sub
        exp  = Just $ NumericDate $ addUTCTime (state ^. tokenTTL) now
        nbf  = Just $ NumericDate now
        iat  = Just $ NumericDate now
        jti  = Just $ UUID.toText uuid
    return $ ClaimsSet iss sub' Nothing exp nbf iat jti Map.empty

-- | A simplified version of 'Crypto.JWT.createJWSJWT' that omits any
-- parameters that can be derived from the Snaplet state.
createJWSJWT' :: (HasJWTState m, MonadIO m)
              => ClaimsSet            -- ^ ClaimSet used to create JWT
              -> m (Either Error JWT) -- ^ Returns either an error or JWT
createJWSJWT' claims = do
    state <- getJWTState
    let (jwt, rng') = withDRG (state ^. rng) $ createJWSJWT (state ^. signingKey) (state ^. header) claims
    putJWTState $ set rng rng' state
    return $ either (Left . JWTError) Right jwt

-- | A simplified version of 'Crypto.JWT.validateJWSJWT' that omits any
-- parameters that can be derived from the Snaplet state.
validateJWSJWT' :: (HasJWTState m, MonadIO m)
                => JWT                   -- ^ JWT to validate
                -> m (Either Error Bool) -- ^ Returns either an error or True
validateJWSJWT' jwt = withJWTState $ \state -> do
    if any (\k -> validateJWSJWT def def k jwt) (state ^. keys)
       then return $ Right True
       else return $ Left InvalidSignature

-- | Validate each claim in the given 'Crypto.JWT.ClaimSet'.
validateClaimsSet :: T.Text            -- ^ Reference issuer
                  -> UTCTime           -- ^ Time used to check not before and expired claims
                  -> NominalDiffTime   -- ^ Clock skew allowed for time checks
                  -> ClaimsSet         -- ^ ClaimsSet to validate
                  -> Either Error Bool -- ^ Return either an error or True
validateClaimsSet iss now skew claims
    | claims ^. claimIss /= iss'        = Left $ InvalidClaimsSet "issuer mismatch"
    | claims ^. claimExp <= head window = Left $ InvalidClaimsSet "expired"
    | claims ^. claimNbf >= last window = Left $ InvalidClaimsSet "time travel"
    | otherwise                         = Right True
  where
    iss' = Just $ fromString iss
    window  = [ Just $ NumericDate $ addUTCTime (-skew) now
              , Just $ NumericDate $ addUTCTime skew now
              ]

-- | A simplified version of 'Snap.Snaplet.JWT.validateClaimSet' that omits any
-- parameters that can be derived from the Snaplet state or current time.
validateClaimsSet' :: (HasJWTState m, MonadIO m)
                   => ClaimsSet             -- ^ ClaimsSet to validate
                   -> m (Either Error Bool) -- ^ Returns either an error or True
validateClaimsSet' claims = withJWTState $ \state -> do
    now <- liftIO getCurrentTime
    return $ validateClaimsSet (state ^. issuer) now (state ^. clockSkew) claims

-- | Combines 'Snap.Snaplet.JWT.validateJWSJWT'' and
-- 'Snap.Snaplet.JWT.validateClaimsSet'' in order to validate both the JWT
-- signature and claims in a single call.
getValidatedClaimsSet :: (HasJWTState m, MonadIO m)
                      => JWT                        -- ^ JWT to validate
                      -> m (Either Error ClaimsSet) -- ^ Returns either an error or a valid ClaimSet
getValidatedClaimsSet jwt = do
    check1 <- validateJWSJWT' jwt
    check2 <- validateClaimsSet' claims
    case lefts [check1, check2] of
        x:_ -> return $ Left x
        _   -> return $ Right claims
  where
    claims = jwtClaimsSet jwt

-- | A modified version of 'Crypto.JOSE.Compact.decodeCompact' that uses
-- 'Snap.Snaplet.JWT.Error' instead of 'Crypto.JOSE.Error.Error'.
decodeCompact' :: (HasJWTState m, MonadIO m)
               => ByteString           -- ^ ByteString to decode
               -> m (Either Error JWT) -- ^ Returns either an error or JWT
decodeCompact' tok = return $ either (Left . JWTError) Right $ decodeCompact tok

-- | A modified version of 'Crypto.JOSE.Compact.encodeCompact' that uses
-- 'Snap.Snaplet.JWT.Error' instead of 'Crypto.JOSE.Error.Error'.
encodeCompact' :: (HasJWTState m, MonadIO m)
               => JWT                         -- ^ JWT to encode
               -> m (Either Error ByteString) -- ^ Returns either an error or ByteString
encodeCompact' jwt = return $ either (Left . JWTError) Right $ encodeCompact jwt

-- | Create a 'Crypto.JWT.ClaimSet', embed the ClaimSet into a
-- 'Crypto.JWT.JWT', and encode the JWT into a
-- 'Data.ByteString.Lazy.ByteString'.
issueToken :: (HasJWTState m, MonadIO m)
           => T.Text                      -- ^ ClaimSet subject
           -> m (Either Error ByteString) -- ^ Returns either an error or a ByteString containing a JWT
issueToken sub = defaultClaimsSet sub >>= createJWSJWT' >>= either (return . Left) encodeCompact'

-- | Decode a 'Crypto.JWT.JWT' from a 'Data.ByteString.Lazy.ByteString' and
-- validate the JWT's signature and claims.
parseToken :: (HasJWTState m, MonadIO m)
           => ByteString                 -- ^ ByteString containing a JWT
           -> m (Either Error ClaimsSet) -- ^ Returns either an error or a valid ClaimSet
parseToken tok = decodeCompact' tok >>= either (return . Left) getValidatedClaimsSet
