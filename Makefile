.PHONY: build test demo clean

build:
	go build -o bin/photofinish ./cmd/photofinish

test:
	go vet ./...
	go test -race ./...

demo: build
	./bin/photofinish demo

clean:
	rm -rf bin
