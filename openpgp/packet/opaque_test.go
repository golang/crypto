// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp/armor"
	"io"
	"testing"
)

// This key contains version 2 public key and signature packets.
// If these are ever supported, this test will need to be updated
// with bad packets that won't parse.
const UnsupportedKeyArmor = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.0.10

mI0CLnoYogAAAQQA1qwA2SuJwfQ5bCQ6u5t20ulnOtY0gykf7YjiK4LiVeRBwHjGq7v30tGV
5Qti7qqRW4Ww7CDCJc4sZMFnystucR2vLkXaSoNWoFm4Fg47NiisDdhDezHwbVPW6OpCFNSi
ZAamtj4QAUBu8j4LswafrJqZqR9336/V3g8Yil2l48kABRG0J0FybWluIE0uIFdhcmRhIDx3
YXJkYUBuZXBoaWxpbS5ydWhyLmRlPoiVAgUQLok2xwXR6zmeWEiZAQE/DgP/WgxPQh40/Po4
gSkWZCDAjNdph7zexvAb0CcUWahcwiBIgg3U5ErCx9I5CNVA9U+s8bNrDZwgSIeBzp3KhWUx
524uhGgm6ZUTOAIKA6CbV6pfqoLpJnRYvXYQU5mIWsNa99wcu2qu18OeEDnztb7aLA6Ra9OF
YFCbq4EjXRoOrYM=
=LPjs
-----END PGP PUBLIC KEY BLOCK-----`

// Test packet.Read error handling in OpaquePacket.Parse,
// which attempts to re-read an OpaquePacket as a supported
// Packet type.
func TestOpaqueParseReason(t *testing.T) {
	armorBlock, err := armor.Decode(bytes.NewBufferString(UnsupportedKeyArmor))
	if err != nil {
		t.Fatalf("armor Decode failed: %v", err)
	}
	or := NewOpaqueReader(armorBlock.Body)
	count := 0
	badPackets := 0
	var uid *UserId
	for {
		op, err := or.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			t.Errorf("#%d: opaque read error: %v", count, err)
			break
		}
		// try to parse opaque packet
		p, err := op.Parse()
		switch pkt := p.(type) {
		case *UserId:
			uid = pkt
		case *OpaquePacket:
			// If an OpaquePacket can't re-parse, packet.Read
			// certainly had its reasons.
			if pkt.Reason == nil {
				t.Errorf("#%d: opaque packet, no reason", count)
			} else {
				badPackets++
			}
		}
		count++
	}

	const expectedBad = 2
	// Test post-conditions, make sure we actually parsed packets as expected.
	if badPackets != expectedBad {
		t.Errorf("unexpected # unparseable packets: %d (want %d)", badPackets, expectedBad)
	}
	if uid == nil {
		t.Errorf("failed to find expected UID in unsupported keyring")
	} else if uid.Id != "Armin M. Warda <warda@nephilim.ruhr.de>" {
		t.Errorf("unexpected UID: %v", uid.Id)
	}
}
