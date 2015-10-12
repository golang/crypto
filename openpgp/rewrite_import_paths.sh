#!/bin/sh

find . -type f -name '*.go' -exec sed {} -i '' -e 's/golang.org\/x\/crypto\/openpgp/github.com\/keybase\/go-crypto\/openpgp' \;
