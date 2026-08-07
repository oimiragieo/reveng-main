// Intentionally divergent candidate source for the no-LLM control arm.
// Always prints WRONG so oracle grades launches_but_divergent vs main.go.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 {
		fmt.Println(os.Args[1])
	} else {
		fmt.Println("ok")
	}
}