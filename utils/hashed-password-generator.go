package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func main() {
	hashed_pass, _ := HashPassword("isthebomb")
	fmt.Println(hashed_pass)
}
