.PHONY: build ui build-ui test e2e demo serve clean

# The binary keeps its .exe suffix on Windows, where the e2e tests look for it.
EXE := $(if $(filter Windows_NT,$(OS)),.exe,)
BIN := bin/photofinish$(EXE)

# build works without a UI build: the binary then serves a page saying that
# the UI was not built. "make build-ui" (make ui, then make build) embeds it.
build:
	go build -o $(BIN) ./cmd/photofinish

ui:
	npm --prefix web ci
	npm --prefix web run build

# The UI must be built before the binary embeds it, also under make -j:
# the order is explicit, not a pair of prerequisites.
build-ui:
	$(MAKE) ui
	$(MAKE) build

test:
	go vet ./...
	go test -race ./...

e2e: build-ui
	npm --prefix web run test:e2e

demo: build
	./$(BIN) demo

serve: build
	./$(BIN) serve

clean:
	rm -rf bin web/node_modules web/test-results web/playwright-report
	rm -rf internal/ui/dist/app
