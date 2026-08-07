// Original micro subject for VRL-LLM honesty dogfood (Linux, CGO_ENABLED=0).
// Prints argv[1] when present, otherwise "ok". Three argv seeds exercise the
// DifferentialOracle without requiring MSVC/gcc (broken on this WSL host).
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
