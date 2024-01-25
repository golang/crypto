module asm

go 1.18

require (
	github.com/mmcloughlin/avo v0.5.0
	golang.org/x/crypto v0.1.0
)

require (
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/sys v0.14.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
)

replace golang.org/x/crypto v0.1.0 => ../../../..
