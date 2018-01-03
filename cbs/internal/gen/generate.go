package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"text/template"

	"golang.org/x/tools/imports"
)

const fname = "types.go"

func main() {
	uints := []int{
		8,
		16,
		24,
		32,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, uints); err != nil {
		log.Fatalf("err: %v", err)
	}

	out, err := imports.Process(fname, buf.Bytes(), nil)
	if err != nil {
		log.Fatalf("err: %v", err)
	}

	if err := ioutil.WriteFile(fname, out, 0666); err != nil {
		log.Fatalf("err: %v", err)
	}
}

var t = template.Must(template.
	New("").
	Funcs(template.FuncMap{
		"itobytes": func(i int) int {
			return i + 1
		},
	}).
	Parse(`
package cbs

{{ range $i, $bits := . }}{{ with $bytes := itobytes $i }}
func (bs *ByteString) PeekU{{ $bits }}() uint {
	return bs.peekU({{ $bytes }})
}

func (bs *ByteString) GetU{{ $bits }}() uint {
	return bs.getU({{ $bytes }})
}

func (bs *ByteString) GetU{{ $bits }}LengthPrefixed() *ByteString  {
	return bs.getULengthPrefixed({{ $bytes }})
}

func (bs *ByteBuilder) PutU{{ $bits }}(n uint) {
	bs.putU({{ $bytes }}, n)
}

func (bs *ByteBuilder) PutU{{ $bits }}LengthPrefixed() *ByteBuilder  {
	return bs.putULengthPrefixed({{ $bytes }})
}
{{ end }}{{ end }}
`))
