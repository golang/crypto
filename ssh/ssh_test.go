// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

var forbiddenStringsFunctions = map[string]bool{
	// Functions that use Unicode-aware case folding.
	"EqualFold":      true,
	"Title":          true,
	"ToLower":        true,
	"ToLowerSpecial": true,
	"ToTitle":        true,
	"ToTitleSpecial": true,
	"ToUpper":        true,
	"ToUpperSpecial": true,

	// Functions that use Unicode-aware spaces.
	"Fields":    true,
	"TrimSpace": true,
}

func TestNoUnicodeStrings(t *testing.T) {
	re := regexp.MustCompile(`(strings|bytes)\.([A-Za-z]+)`)
	if err := fs.WalkDir(os.DirFS("."), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}

		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for lineNum, line := range strings.Split(string(contents), "\n") {
			for _, match := range re.FindAllStringSubmatch(line, -1) {
				if !forbiddenStringsFunctions[match[2]] {
					continue
				}
				t.Errorf("disallowed call to %s at %s:%d", match[0], path, lineNum+1)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
