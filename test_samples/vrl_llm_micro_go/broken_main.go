// Intentionally divergent candidate source for the no-LLM control arm.
// Always prints WRONG so oracle grades launches_but_divergent vs main.go.
package main

import (
	"fmt"
	"os"
)

func main() {
	_ = os.Args
	fmt.Println("WRONG")
}
