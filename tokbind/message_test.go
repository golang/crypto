package tokbind

import (
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/cbs"
)

type data struct {
	secTokenBinding string
	ekm             string
	tbh             []string
	tbm             *TokenBindingMessage
}

var cases = []data{
	// oauth-token-binding examples
	{
		secTokenBinding: "AIkAAgBBQLgtRpWFPN66kxhxGrtaKrzcMtHw7HV8yMk_-MdRXJXbDMYxZCWnCASRRrmHHHL5wmpP3bhYt0ChRDbsMapfh_QAQN1He3Ftj4Wa_S_fzZVns4saLfj6aBoMSQW6rLs19IIvHze7LrGjKyCfPTKXjajebxp-TLPFZCc0JTqTY5_0MBAAAA",
		ekm:             "7LsNP3BT1aHHdXdk6meEWjtSkiPVLb7YS6iHp-JXmuE",
		tbh: []string{
			"7NRBu9iDdJlYCTOqyeYuLxXv0blEA-yTpmGIrAwKAws",
		},
	},
	{
		secTokenBinding: "ARIAAgBBQJFXJir2w4gbJ7grBx9uTYWIrs9V50-PW4ZijegQ0LUM-_bGnGT6DizxUK-m5n3dQUIkeH7ybn6wb1C5dGyV_IAAQDDFToFrHt41Zppq7u_SEMF_E-KimAB-HewWl2MvZzAQ9QKoWiJCLFiCkjgtr1RrA2-jaJvoB8o51DTGXQydWYkAAAECAEFAuC1GlYU83rqTGHEau1oqvNwy0fDsdXzIyT_4x1FcldsMxjFkJacIBJFGuYcccvnCak_duFi3QKFENuwxql-H9ABAMcU7IjJOUA4IyE6YoEcfz9BMPQqwM5M6hw4RZNQd58fsTCCslQE_NmNCl9JXy4NkdkEZBxqvZGPr0y8QZ_bmAwAA",
		ekm:             "4jTc5e1QpocqPTZ5l6jsb6pRP18IFKdwwPvasYjn1-E",
		tbh: []string{
			"Cn69TXPEB65Ek8tiG3i1bS5l6wH8iMwOuSo-BxXe_dk",
			"7NRBu9iDdJlYCTOqyeYuLxXv0blEA-yTpmGIrAwKAws",
		},
	},
	// oidc examples
	{
		secTokenBinding: "AIkAAgBBQKzyIrmcY_YCtHVoSHBut69vrGfFdy1_YKTZfFJv6BjrZsKD9b9FRzSBxDs1twTqnAS71M1RBumuihhI9xqxXKkAQIMi9gthwFtmF1lpXioRsIlQA8vZOKQ0hrJE1_610h0h-IX-O_WllivUBoyLV7ypArE15whKaDrfwsolflmWfPsAAA",
		ekm:             "1mOiLC0IFA5SMBQQVvd48VSKNuF89USGw2_UBbWik34",
		tbh: []string{
			"suMuxh_IlrP-Zrj33LuQOQ5rX039cmBe-wt2df3BrUQ",
		},
	},
	{
		secTokenBinding: "ARIAAgBBQCfsI1D1sTq5mvT_2H_dihNIvuHJCHGjHPJchPavNbGrOo26-2JgT_IsbvZd4daDFbirYBIwJ-TK1rh8FzrC-psAQO4Au9xPupLSkhwT9Yn9aSvHXFsMLh4d4cEBKGP1clJtsfUFGDw-8HQSKwgKFN3WfZGq27y8NB3NAM1oNzvqVOIAAAECAEFArPIiuZxj9gK0dWhIcG63r2-sZ8V3LX9gpNl8Um_oGOtmwoP1v0VHNIHEOzW3BOqcBLvUzVEG6a6KGEj3GrFcqQBA9YxqHPBIuDui_aQ1SoRGKyBEhaG2i-Wke3erRb1YwC7nTgrpqqJG3z1P8bt7cjZN6TpOyktdSSK7OJgiApwG7AAA",
		ekm:             "r4FNRMOUG_0gQQKyDGwEiCE6v8lmpsV99GZddteFIYQ",
		tbh: []string{
			"dMGhw4oodOWSNZp3bG6AUU51iwMWDvTXl_4zOyjOgz8",
			"suMuxh_IlrP-Zrj33LuQOQ5rX039cmBe-wt2df3BrUQ",
		},
	},
}

func runTest(t *testing.T, tf func(*testing.T, data)) {
	t.Helper()
	for i, c := range cases {
		tbm, err := ParseSecTokenBinding(c.secTokenBinding)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		c.tbm = tbm

		t.Run(fmt.Sprintf("(%d)", i), func(t *testing.T) {
			tf(t, c)
		})
	}
}

func TestVerify(t *testing.T) {
	runTest(t, func(t *testing.T, c data) {
		ekmb, err := base64.RawURLEncoding.DecodeString(c.ekm)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		for _, tb := range c.tbm.TokenBindings {
			if !tb.Verify(ekmb) {
				t.Errorf("invalid signature on tokenbinding")
			}
		}
	})
}

func TestTokenBindingHash(t *testing.T) {
	runTest(t, func(t *testing.T, c data) {
		for i, tb := range c.tbm.TokenBindings {
			hash := tb.TokenBindingID.TokenBindingHash()
			if hash != c.tbh[i] {
				t.Errorf("bad tbh:\n\tsaw:\t%v\n\twant:\t%v", hash, c.tbh[i])
			}
		}
	})
}

func TestRoundTrip(t *testing.T) {
	runTest(t, func(t *testing.T, c data) {
		bb := cbs.NewByteBuilder()
		c.tbm.marshal(bb)

		tbmb := base64.RawURLEncoding.EncodeToString(bb.Bytes())
		if c.secTokenBinding != tbmb {
			t.Fatalf("unexpected binding\nsaw:\t%s\nwant:\t%s", c.secTokenBinding, tbmb)
		}
	})
}
