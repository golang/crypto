package knownhosts

import (
	"fmt"
	"strings"
	"testing"
)

func TestNewFromReader(t *testing.T) {
	str := fmt.Sprintf("server*.domain %s", edKeyStr)

	_, err := NewFromReader(strings.NewReader(str))
	if err != nil {
		t.Fatalf("cannot read from string: %v", err)
	}

}
