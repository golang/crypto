package tokbind

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"

	"golang.org/x/crypto/cbs"
)

const (
	ekmLabel = "EXPORTER-Token-Binding"

	header = "Sec-Token-Binding"
)

type serverRt struct {
}

func (rt *serverRt) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, nil
}

func ParseSecTokenBinding(e string) (*TokenBindingMessage, error) {
	b, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, err
	}

	out := &TokenBindingMessage{}
	out.unmarshal(cbs.NewByteString(b))
	return out, nil
}

func (tbid *TokenBindingID) TokenBindingHash() string {
	bb := cbs.NewByteBuilder()
	tbid.marshal(bb)
	b := sha256.Sum256(bb.Bytes())
	return base64.RawURLEncoding.EncodeToString(b[:])

}
