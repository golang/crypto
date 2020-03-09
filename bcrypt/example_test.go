package bcrypt_test

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func ExampleGenerateFromPassword() {
	password := []byte("mypassword")
	securedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	fmt.Println(bcrypt.CompareHashAndPassword(securedPassword, password))
	// Output: <nil>
}
