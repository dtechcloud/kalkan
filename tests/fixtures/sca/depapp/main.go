// kalkan depapp fixture. Never deploy.
package main

import (
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func main() {
	tag, err := language.Parse(os.Getenv("LANG_TAG"))
	if err != nil {
		fmt.Println("invalid language tag")
		return
	}
	fmt.Println(tag.String())
}
