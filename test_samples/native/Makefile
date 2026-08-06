.PHONY: all hello_c hello_go clean

all: hello_c hello_go

hello_c:
	mkdir -p hello_c/build
	cc -std=c99 -O0 -g -o hello_c/build/hello_c hello_c/hello.c

hello_go:
	mkdir -p hello_go/build
	cd hello_go && CGO_ENABLED=0 go build -trimpath -o build/hello_go .

clean:
	rm -rf hello_c/build hello_go/build
