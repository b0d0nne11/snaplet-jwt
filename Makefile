compiler := $(shell realpath --relative-to=. `stack path --compiler-exe`)

default: build

${compiler}:
	stack setup

build: ${compiler}
	stack build --no-copy-bins

test: ${compiler}
	stack test

docs: ${compiler}
	stack haddock --open

clean:
	stack clean --full
