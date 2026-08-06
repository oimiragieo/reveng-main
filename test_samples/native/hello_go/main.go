package main

import (
	"fmt"
	"os"
)

func usage(stream *os.File) {
	fmt.Fprint(stream, "Usage: hello_go [--help|--version]\n")
	fmt.Fprint(stream, "  --help     Show this help message\n")
	fmt.Fprint(stream, "  --version  Print version and exit\n")
}

func main() {
	if len(os.Args) == 1 {
		usage(os.Stdout)
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "--help" {
		usage(os.Stdout)
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Fprint(os.Stdout, "hello_go 1.0.0\n")
		os.Exit(0)
	}
	usage(os.Stderr)
	os.Exit(2)
}
