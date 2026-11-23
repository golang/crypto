// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bcrypt_test

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func ExampleGenerateFromPassword() {
	password := []byte("mypassword")
	storedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	if err := bcrypt.CompareHashAndPassword(storedPassword, password); err != nil {
        	log.Fatal("invalid password!")
    	}
	// Output: <nil>
}
