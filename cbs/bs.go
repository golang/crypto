package cbs

import (
	"bytes"
)

func NewByteString(data []byte) *ByteString {
	return &ByteString{
		data: data,
	}
}

type ByteString struct {
	data []byte
}

func (bs *ByteString) Get(len int) *ByteString {
	defer bs.Skip(len)
	return bs.Peek(len)
}

func (bs *ByteString) Peek(len int) *ByteString {
	out := &ByteString{data: bs.data[:len]}
	return out
}

func (bs *ByteString) Skip(len int) {
	bs.data = bs.data[len:]
}

func (bs *ByteString) Clone() *ByteString {
	return &ByteString{
		data: bs.data,
	}
}

func (bs *ByteString) Bytes() []byte {
	return bs.data
}

func (bs *ByteString) getU(ulen int) uint {
	defer bs.Skip(ulen)
	return bs.peekU(ulen)
}

func (bs *ByteString) peekU(ulen int) uint {
	var out uint
	for _, b := range bs.Peek(ulen).data {
		out <<= 8
		out |= uint(b)
	}
	return out
}

func (bs *ByteString) getULengthPrefixed(ulen int) *ByteString {
	return bs.Get(int(bs.getU(ulen)))
}

func NewByteBuilder() *ByteBuilder {
	return &ByteBuilder{
		buf: &bytes.Buffer{},
	}
}

type ByteBuilder struct {
	buf *bytes.Buffer

	child     *ByteBuilder
	off, ulen int
}

func (bb *ByteBuilder) Put(b []byte) {
	bb.Finish()
	bb.buf.Write(b)
}

func (bb *ByteBuilder) Bytes() []byte {
	return bb.buf.Bytes()
}

func (bb *ByteBuilder) Finish() {
	if bb.child == nil {
		return
	}

	bb.child.Finish()
	bb.child.buf = nil

	lb := bb.buf.Bytes()[bb.off : bb.off+bb.ulen]
	size := len(bb.buf.Bytes()[bb.off+bb.ulen:])

	for i := 0; i < bb.ulen; i++ {
		lb[i] = byte(size >> uint((bb.ulen-i-1)*8))
	}

	bb.child = nil
	bb.off, bb.ulen = 0, 0
}

func (bb *ByteBuilder) putU(ulen int, n uint) {
	b := make([]byte, ulen)
	for i := 0; i < ulen; i++ {
		b[i] = byte(n >> uint((ulen-i-1)*8))
	}
	bb.Put(b)
}

func (bb *ByteBuilder) putULengthPrefixed(ulen int) *ByteBuilder {
	bb.Finish()

	bb.off = len(bb.buf.Bytes())
	bb.ulen = ulen

	const zero = byte(0)
	for i := 0; i < ulen; i++ {
		bb.buf.WriteByte(zero)
	}

	bb.child = &ByteBuilder{
		buf: bb.buf,
	}

	return bb.child
}

//go:generate go run ./internal/gen/generate.go
