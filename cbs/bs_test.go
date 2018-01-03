package cbs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	data := []byte{'\x0a', '\x0b'}
	cs := []struct {
		build  func(bb *ByteBuilder, t *testing.T)
		parse  func(bs *ByteString, t *testing.T)
		expect string
	}{
		{
			build: func(bb *ByteBuilder, t *testing.T) {
			},
			expect: "",
			parse: func(bs *ByteString, t *testing.T) {
			},
		},
		{
			build: func(bb *ByteBuilder, t *testing.T) {
				bb.PutU8(8)
				bb.PutU16(8)
				bb.PutU24(8)
				bb.PutU32(8)
			},
			expect: "08000800000800000008",
			parse: func(bs *ByteString, t *testing.T) {
				const expectedCount = 4
				parsed := 0

				if bs.GetU8() == 8 {
					parsed |= 1 << 0
				}

				if bs.GetU16() == 8 {
					parsed |= 1 << 1
				}

				if bs.GetU24() == 8 {
					parsed |= 1 << 2
				}

				if bs.GetU32() == 8 {
					parsed |= 1 << 3
				}

				expect := (1 << expectedCount) - 1
				if parsed != expect {
					t.Fatalf("expected %b correct parses but saw %b", expect, parsed)
				}
			},
		},
		{
			build: func(bb *ByteBuilder, t *testing.T) {
				if bb := bb.PutU8LengthPrefixed(); true {
					bb.Put([]byte{'\x0a', '\x0b'})
				}
				bb.Finish()
			},
			expect: "020a0b",
		},
		{
			build: func(bb *ByteBuilder, t *testing.T) {
				if bb := bb.PutU8LengthPrefixed(); true {
					bb.Put(data)
				}
				if bb := bb.PutU16LengthPrefixed(); true {
					bb.Put(data)
				}
				if bb := bb.PutU24LengthPrefixed(); true {
					bb.Put(data)
				}
				if bb := bb.PutU32LengthPrefixed(); true {
					bb.Put(data)
				}
				bb.Finish()
			},
			expect: "020a0b00020a0b0000020a0b000000020a0b",
			parse: func(bs *ByteString, t *testing.T) {
				const expectedCount = 4
				parsed := 0

				if bytes.Compare(bs.GetU8LengthPrefixed().Bytes(), data) == 0 {
					parsed |= 1 << 0
				}

				if bytes.Compare(bs.GetU16LengthPrefixed().Bytes(), data) == 0 {
					parsed |= 1 << 1
				}

				if bytes.Compare(bs.GetU24LengthPrefixed().Bytes(), data) == 0 {
					parsed |= 1 << 2
				}

				if bytes.Compare(bs.GetU32LengthPrefixed().Bytes(), data) == 0 {
					parsed |= 1 << 3
				}

				expect := (1 << expectedCount) - 1
				if parsed != expect {
					t.Fatalf("expected %b correct parses but saw %b", expect, parsed)
				}
			},
		},
		{
			build: func(bb *ByteBuilder, t *testing.T) {
				innerbb := bb.PutU8LengthPrefixed()
				innerbb.Put(data)
				innerbb = innerbb.PutU16LengthPrefixed()
				innerbb.Put(data)
				innerbb = innerbb.PutU24LengthPrefixed()
				innerbb.Put(data)
				innerbb = innerbb.PutU32LengthPrefixed()
				innerbb.Put(data)
				bb.Put(data)
			},
			expect: "110a0b000d0a0b0000080a0b000000020a0b0a0b",
			parse: func(bs *ByteString, t *testing.T) {
				const expectedCount = 4
				parsed := 0

				bs = bs.GetU8LengthPrefixed()
				if bytes.Compare(bs.Get(2).Bytes(), data) == 0 {
					parsed |= 1 << 0
				}

				bs = bs.GetU16LengthPrefixed()
				if bytes.Compare(bs.Get(2).Bytes(), data) == 0 {
					parsed |= 1 << 1
				}

				bs = bs.GetU24LengthPrefixed()
				if bytes.Compare(bs.Get(2).Bytes(), data) == 0 {
					parsed |= 1 << 2
				}

				bs = bs.GetU32LengthPrefixed()
				if bytes.Compare(bs.Get(2).Bytes(), data) == 0 {
					parsed |= 1 << 3
				}

				expect := (1 << expectedCount) - 1
				if parsed != expect {
					t.Fatalf("expected %b correct parses but saw %b", expect, parsed)
				}
			},
		},
	}
	for i, c := range cs {
		t.Run(fmt.Sprintf("(%d)", i), func(t *testing.T) {
			bb := NewByteBuilder()
			c.build(bb, t)

			got := hex.EncodeToString(bb.Bytes())
			if c.expect != got {
				t.Fatalf("unexpected:\n\twant:\t%q\n\tsaw:\t%q", c.expect, got)
			}

			if c.parse != nil {
				bs := NewByteString(bb.Bytes())
				c.parse(bs, t)
			}
		})
	}
}
