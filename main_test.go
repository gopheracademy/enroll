package main

import "testing"
import "fmt"

func TestCreate(t *testing.T) {
	script := createUser("bketelsen", "ncc1701c")
	fmt.Println(script)

}
