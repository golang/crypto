package md5crypt

import (
	"bytes"
	"testing"
)

func TestDecodeSupportedSalt(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		salt, want string
		wantMagic  []byte
	}{
		{"$1$", "", MD5Magic},
		{"$1$a", "a", MD5Magic},
		{"$1$a$", "a", MD5Magic},
		{"$1$ab", "ab", MD5Magic},
		{"$1$ab$", "ab", MD5Magic},
		{"$1$abcdefgh", "abcdefgh", MD5Magic},
		{"$1$abcdefgh$", "abcdefgh", MD5Magic},
		{"$1$abcdefghi", "abcdefgh", MD5Magic},
		{"$1$abcdefghi$", "abcdefgh", MD5Magic},
		{"$apr1$", "", APR1Magic},
		{"$apr1$a", "a", APR1Magic},
		{"$apr1$a$", "a", APR1Magic},
		{"$apr1$ab", "ab", APR1Magic},
		{"$apr1$ab$", "ab", APR1Magic},
		{"$apr1$abcdefgh", "abcdefgh", APR1Magic},
		{"$apr1$abcdefgh$", "abcdefgh", APR1Magic},
		{"$apr1$abcdefghi", "abcdefgh", APR1Magic},
		{"$apr1$abcdefghi$", "abcdefgh", APR1Magic},
	} {
		magic, got, err := decodeSalt([]byte(tt.salt))
		if err != nil {
			t.Errorf("Error decoding salt %q: %v.", tt.salt, err)
		}
		if !bytes.Equal(magic, tt.wantMagic) {
			t.Errorf("Decoded magic is %q, want %q.", magic, tt.wantMagic)
		}
		if string(got) != tt.want {
			t.Errorf("Decoded salt %q: got %q, want %q.", tt.salt, got, tt.want)
		}

	}
}

func TestDecodeUnsupportedSalt(t *testing.T) {
	_, _, err := decodeSalt([]byte("$2$whatever$"))
	if err != ErrUnsupportedSalt {
		t.Errorf("Decoding unsupported salt returned error %v, want %v.", err, ErrUnsupportedSalt)
	}
}

func TestGenerateFromPassword(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		password, salt, want string
	}{
		// test vectors generated using htpasswd(1) and crypt(3) on a Linux system.
		{"apache", "$apr1$uvV3T7fu", "$apr1$uvV3T7fu$gvDOBExDieXrhdDxL8.hb."},
		{"apache", "$apr1$uvV3T7fu$", "$apr1$uvV3T7fu$gvDOBExDieXrhdDxL8.hb."},
		{"apache", "$apr1$uvV3T7fu$gvDOBExDieXrhdDxL8.hb.", "$apr1$uvV3T7fu$gvDOBExDieXrhdDxL8.hb."},
		{"topsecret", "$apr1$iKNcB2Be$", "$apr1$iKNcB2Be$.IZPKdGtT8wV99cJ2cmm21"},
		{"topsecret", "$1$", "$1$$s/sSkcXFvhLMpizXR5c7/0"},
		{"topsecret", "$1$$", "$1$$s/sSkcXFvhLMpizXR5c7/0"},
	} {
		got, err := GenerateFromPassword([]byte(tt.password), []byte(tt.salt))
		if err != nil {
			t.Errorf("GenerateFromPassword(%q, %q) returned error %v.", tt.password, tt.salt, err)
		}
		if string(got) != tt.want {
			t.Errorf("GenerateFromPassword(%q, %q): got %q, want %q.", tt.password, tt.salt, got, tt.want)
		}
		if cap(got) != len(tt.want) {
			t.Errorf("Returned slice preallocated more memory than required: got %d, want %d.", cap(got), len(tt.want))
		}
	}
}

func TestGenerateFromPasswordUnsupported(t *testing.T) {
	t.Parallel()
	_, err := GenerateFromPassword([]byte("topsecret"), []byte("$2$whatever$"))
	if err != ErrUnsupportedSalt {
		t.Errorf("GenerateFromPassword with unsupported salt returned error %v, want %v.", err, ErrUnsupportedSalt)
	}
}

func TestCompareHashAndPassword(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		password, hashedPassword string
	}{
		{"apache", "$apr1$uvV3T7fu$gvDOBExDieXrhdDxL8.hb."},
		{"topsecret", "$apr1$iKNcB2Be$.IZPKdGtT8wV99cJ2cmm21"},
		{"topsecret", "$1$$s/sSkcXFvhLMpizXR5c7/0"},
		{"topsecret", "$1$ALwsXB9w$B/FdgWMtcav/q8kuxQ/BK1"},
	} {
		if err := CompareHashAndPassword([]byte(tt.hashedPassword), []byte(tt.password)); err != nil {
			t.Errorf("CompareHashAndPassword(%q, %q) returned error %q, want nil.", tt.hashedPassword, tt.password, err)
		}
		if err := CompareHashAndPassword([]byte(tt.hashedPassword), []byte(tt.password+"x")); err == nil {
			t.Errorf("CompareHashAndPassword(%q, %q) returned no error.", tt.hashedPassword, tt.password+"x")
		}
	}
}

func TestCompareHashAndPasswordUnsupported(t *testing.T) {
	t.Parallel()
	if err := CompareHashAndPassword([]byte("topsecret"), []byte("9yH.Z916aam4E")); err != ErrUnsupportedSalt {
		t.Errorf("CompareHashAndPassword returned error %v for unsupported salt, want %v.", err, ErrUnsupportedSalt)
	}
}
