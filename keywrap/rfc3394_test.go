// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keywrap

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

const testRSAImportKey string = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCvpelnsOxdzHmQLCLEu+y1MzJH91/jO9k0aKTMAd5q0nQJGAQt
b6HwvfCOGpvqeGnUECIaXyq32tgtPgOfSCqFsTdN7aTxYbyrp//wbzbVRIc3mjPw
DbKoMXdl/xrY7wr/MbG5xPDh3huJKJKMYV9hDfrazL1sRGGU7wM3jg7tpQIDAQAB
AoGAFeTfYB5siBCZwn/N4anvCnMUPGY4XJG0NFUq3YcKG1SaRBvrQWKd0+1JE917
O9HAlz9fkNv17i7oLVOCjhMnwYdwDGmMq8FFgzglb51ZwOxuUeCTAlMfVZS5jVuW
kCMFde1XkShFcULLMB+j12Hcbm08ndE9QNT83FHeqvVlX+ECQQDIgeFptd+a8s9v
C2yyClxzcyFwxnv7uZdZIYHuUwA8CL1MTJhFwp6EkZKU7esKSdBxR+c+Dl0Z5KXa
s7f2zX7JAkEA4EK7R8Mnxw/qpg2vvoJ8cjX0Cb+X6q+OYhfWziCSrABxANTl1ZeS
yL5M2wg4vkk7ciQEY+/FG1R/jk9Iz18Z/QJAIEC0L7rvww73yxb9Xw5HnNKSOH/V
BcLu04mOSvXS/dUyDgnsHJyXvx9jgs1al4cUHoTAb70DwNyEyU9LcknP8QJAad+X
Qv3jXZsqEFMN0UcRMWo/WArX0bgn5C+U/aNrG0DqGJZqGzh/173f0thC0bMJGY3f
dL7Rs2FlBu5vVVd0kQJAJNpC+9Yy0ajpUJTJcG4Dfs22jECPdFt8jbYDXTDsQQst
pC1T9h5XIcAK0rNpLBbr9YjOrniiLZhp4LwJNDzmnA==
-----END RSA PRIVATE KEY-----
`

func TestWrapKey(t *testing.T) {

	type TestInput struct {
		Key            string
		KeyData        string
		ExpectedOutput string
	}

	tes := []TestInput{
		{"000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
			"96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF",
			"64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607",
			"031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607",
			"A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
	}

	for _, test := range tes {
		t.Run(test.Key, func(t *testing.T) {
			a, _ := hex.DecodeString(test.Key)
			b, _ := hex.DecodeString(test.KeyData)
			o, e := WrapKey(a, b, nil)
			if e != nil {
				t.Log(e.Error())
				t.Fail()
			}

			if strings.ToLower(hex.EncodeToString(o)) != strings.ToLower(test.ExpectedOutput) {
				t.Fail()
			}
		})
	}

}

func TestUnWrapKey(t *testing.T) {
	type TestInput struct {
		Key            string
		KeyData        string
		ExpectedOutput string
	}
	//test vectors are from RFC-3394
	tes := []TestInput{
		{"000102030405060708090A0B0C0D0E0F", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5", "00112233445566778899AABBCCDDEEFF"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
			"00112233445566778899AABBCCDDEEFF"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
			"00112233445566778899AABBCCDDEEFF"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
			"00112233445566778899AABBCCDDEEFF0001020304050607"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
			"00112233445566778899AABBCCDDEEFF0001020304050607"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"},
	}

	for _, test := range tes {
		t.Run(test.Key, func(t *testing.T) {
			a, _ := hex.DecodeString(test.Key)
			b, _ := hex.DecodeString(test.KeyData)
			o, e := UnWrapKey(a, b)
			if e != nil {
				t.Log(e.Error())
				t.Fail()
			}

			if strings.ToLower(hex.EncodeToString(o[8:])) != strings.ToLower(test.ExpectedOutput) {
				t.Fail()
			}
		})
	}

}

func TestWrapKeyPadded(t *testing.T) {

	type TestInput struct {
		Key            string
		KeyData        string
		ExpectedOutput string
	}

	tes := []TestInput{
		{"5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", "c37b7e6492584340bed12207808941155068f738", "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"},
		{"5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", "466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f"},
		{"000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "2cef0c9e30de26016c230cb78bc60d51b1fe083ba0c79cd5"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
			"5fd7477fdc165910c8e5dd891a421b10db10362fd293b128"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF",
			"afc860015ffe2d75bedf43c444fe58f4ad9d89c4ec71e23b"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607",
			"39c3bf03c71e0d49bd968f26397b3855e5e89eaafd256edbc2f1d03f3266f3f4"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607",
			"b9f05286f13fc80d1f8614a1acac931f293f66d7a3bb3811fb568f7108ec6210"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"4a8029243027353b0694cf1bd8fc745bb0ce8a739b19b1960b12426d4c39cfeda926d103ab34e9f6"},
	}

	for _, test := range tes {
		t.Run(test.Key, func(t *testing.T) {
			a, _ := hex.DecodeString(test.Key)
			b, _ := hex.DecodeString(test.KeyData)
			o, e := WrapKeyPadded(a, b)
			if e != nil {
				t.Log(e.Error())
				t.Fail()
			}
			if strings.ToLower(hex.EncodeToString(o)) != strings.ToLower(test.ExpectedOutput) {
				t.Fail()
			}
		})
	}

	t.Run("rsa", func(t *testing.T) {
		a, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		b := []byte(testRSAImportKey)
		o, e := WrapKeyPadded(a, b)
		if e != nil {
			t.Log(e.Error())
			t.Fail()
		}

		t.Log(base64.StdEncoding.EncodeToString(o))

		if strings.ToLower(hex.EncodeToString(o)) != strings.ToLower("1f9ee47712984fe5f9b1b3ec6f53cb0e520f54240364a162412e12964fb4398ff035249c74e40357732597ceb1d56eeb0eb1ccc5f7f35f50fd609164b9e88b2a05e45eb7a74d6476287ba3a3f641409e15220e0070ea70a2db0336e98af614f279cecdeb90ddb7bafff6be0a9ea8c1f247da26618a277976fcf75f32256ec3e569fc126b4d37fab6536bab5e002029abb0593f62a2a49ffb0e493b1f53738dc8ff906199204488af9b1dc8ff736e065c605b27b59236e79b8e46408644ab843f684c83bbad10321fdf21ac491cd7c6208ba9fe606b6a74fbdf43afc3515863efe07522fdb111a2210c2497a984a3a48a3d4fcf1b050f17046e82f0ff2acf770b3e2fe69340b68102021066426ba562f046c18981d4fda1908e03c22df1f05739bc5ec904ee32f58abcbdf1c931e59e5e036aea4a027f7db4e0140f53266f0185cbf6b77c4520d3de7d9e9c04b1ae50857580be926de7fa6336bfe8d4a3aecbf8155060d4a360d67e787fe074bddd413badf5b5ae0a9230357b00b952c869e0779f18346b8cac9baf16c1bf54c70488c3738841c348e19325721018ed35ce27280e6e09c365913a2351fca2209b95a7b2a7d681a6975d1a4b6dbd3d9f148996ae3ccb5dcec937e34a3a0ddaf97fe8aa4a00bd1cde0cc55a007263450b3a9a72bfc4d933bd416362135a910d9f79798c5ce6bda1adcc92652a7551372d69033359f0c4a434ed548c6573616e9b3a0fd3777bc6108eff685364e907c99918a30dce08de42394a52ed8b1fcffb8b3ad88bcaf9cfba3b5b923ee6109bdacdeea39793cdc6778000e5e76fa863ecee0b971645dc3b1dad493d0745f26a85483c3473ef4b5782ec2473283e034f919ff0a8ebbf732e65ff691993387d24211b3879a0c642c5945ac0d87b242c7edb944d093e8e38f57fa8c7a617d4a9669eea15534f9aabe32c102b74b67a43f4420f9612d7bfc18bfbfa791b047f7c92e97780ff44321334fca74cc1d09897bd4c572aeaa59ba9ebc380eb96cfb1c5a1186240f21be69f28db92f565cd26c9a1bbbb750277fafbcc34a64e774a1b3c22cceb6bc68411021c37de4dc432b21607e4d807b8a7038933a784b623e785f334410167da15d13f53dc06a9f8c57af77549364dcc3a80660650e0034e4f0e630504d0e8f2c072d8bb2c78c71e1f976daf824664936f6ef962f06ef1deabfe574a2cf8cb2f6988f270d895d33776b7e21b05d143aaada77483474a5dac81569205252f93aa697b") {
			t.Fail()
		}
	})

}

func TestUnwrapPadded(t *testing.T) {
	type TestInput struct {
		Key            string
		KeyData        string
		ExpectedOutput string
	}

	tes := []TestInput{
		{"5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a", "c37b7e6492584340bed12207808941155068f738"},
		{"5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", "afbeb0f07dfbf5419200f2ccb50bb24f", "466f7250617369"},
		{"000102030405060708090A0B0C0D0E0F", "2cef0c9e30de26016c230cb78bc60d51b1fe083ba0c79cd5", "00112233445566778899AABBCCDDEEFF"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "5fd7477fdc165910c8e5dd891a421b10db10362fd293b128",
			"00112233445566778899AABBCCDDEEFF"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "afc860015ffe2d75bedf43c444fe58f4ad9d89c4ec71e23b",
			"00112233445566778899AABBCCDDEEFF"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "39c3bf03c71e0d49bd968f26397b3855e5e89eaafd256edbc2f1d03f3266f3f4",
			"00112233445566778899AABBCCDDEEFF0001020304050607"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "b9f05286f13fc80d1f8614a1acac931f293f66d7a3bb3811fb568f7108ec6210",
			"00112233445566778899AABBCCDDEEFF0001020304050607"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "4a8029243027353b0694cf1bd8fc745bb0ce8a739b19b1960b12426d4c39cfeda926d103ab34e9f6",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"},
	}

	for _, test := range tes {
		t.Run(test.Key, func(t *testing.T) {
			a, _ := hex.DecodeString(test.Key)
			b, _ := hex.DecodeString(test.KeyData)
			o, e := UnwrapPadded(a, b)
			if e != nil {
				t.Log(e.Error())
				t.Fail()
			}
			if strings.ToLower(hex.EncodeToString(o)) != strings.ToLower(test.ExpectedOutput) {
				t.Fail()
			}
		})
	}

	t.Run("rsa", func(t *testing.T) {
		a, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		b, _ := hex.DecodeString("1f9ee47712984fe5f9b1b3ec6f53cb0e520f54240364a162412e12964fb4398ff035249c74e40357732597ceb1d56eeb0eb1ccc5f7f35f50fd609164b9e88b2a05e45eb7a74d6476287ba3a3f641409e15220e0070ea70a2db0336e98af614f279cecdeb90ddb7bafff6be0a9ea8c1f247da26618a277976fcf75f32256ec3e569fc126b4d37fab6536bab5e002029abb0593f62a2a49ffb0e493b1f53738dc8ff906199204488af9b1dc8ff736e065c605b27b59236e79b8e46408644ab843f684c83bbad10321fdf21ac491cd7c6208ba9fe606b6a74fbdf43afc3515863efe07522fdb111a2210c2497a984a3a48a3d4fcf1b050f17046e82f0ff2acf770b3e2fe69340b68102021066426ba562f046c18981d4fda1908e03c22df1f05739bc5ec904ee32f58abcbdf1c931e59e5e036aea4a027f7db4e0140f53266f0185cbf6b77c4520d3de7d9e9c04b1ae50857580be926de7fa6336bfe8d4a3aecbf8155060d4a360d67e787fe074bddd413badf5b5ae0a9230357b00b952c869e0779f18346b8cac9baf16c1bf54c70488c3738841c348e19325721018ed35ce27280e6e09c365913a2351fca2209b95a7b2a7d681a6975d1a4b6dbd3d9f148996ae3ccb5dcec937e34a3a0ddaf97fe8aa4a00bd1cde0cc55a007263450b3a9a72bfc4d933bd416362135a910d9f79798c5ce6bda1adcc92652a7551372d69033359f0c4a434ed548c6573616e9b3a0fd3777bc6108eff685364e907c99918a30dce08de42394a52ed8b1fcffb8b3ad88bcaf9cfba3b5b923ee6109bdacdeea39793cdc6778000e5e76fa863ecee0b971645dc3b1dad493d0745f26a85483c3473ef4b5782ec2473283e034f919ff0a8ebbf732e65ff691993387d24211b3879a0c642c5945ac0d87b242c7edb944d093e8e38f57fa8c7a617d4a9669eea15534f9aabe32c102b74b67a43f4420f9612d7bfc18bfbfa791b047f7c92e97780ff44321334fca74cc1d09897bd4c572aeaa59ba9ebc380eb96cfb1c5a1186240f21be69f28db92f565cd26c9a1bbbb750277fafbcc34a64e774a1b3c22cceb6bc68411021c37de4dc432b21607e4d807b8a7038933a784b623e785f334410167da15d13f53dc06a9f8c57af77549364dcc3a80660650e0034e4f0e630504d0e8f2c072d8bb2c78c71e1f976daf824664936f6ef962f06ef1deabfe574a2cf8cb2f6988f270d895d33776b7e21b05d143aaada77483474a5dac81569205252f93aa697b")
		o, e := UnwrapPadded(a, b)
		if e != nil {
			t.Log(e.Error())
			t.Fail()
		}
		if strings.Compare(string(o), testRSAImportKey) != 0 {
			t.Fail()
		}
	})
}
