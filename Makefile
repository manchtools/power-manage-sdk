.PHONY: generate generate-go generate-ts gofmt-gen clean install-tools

# Proto source directory
PROTO_DIR := proto
# Generated output directory
GEN_DIR := gen

install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest
	go install github.com/favadi/protoc-go-inject-tag@latest

generate: generate-go inject-tags gofmt-gen generate-ts

# protoc-go-inject-tag rewrites struct tags but does NOT re-run gofmt
# afterwards, so its output can leave the generated .pb.go files with
# multi-field struct alignment that gofmt -l flags. Run gofmt -w over
# the gen directory once at the end of the Go pipeline to keep the
# committed gen files clean against `gofmt -l ./...`.
gofmt-gen:
	gofmt -w $(GEN_DIR)/go

generate-go:
	@mkdir -p $(GEN_DIR)/go/pm/v1
	protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(GEN_DIR)/go \
		--go_opt=paths=source_relative \
		--connect-go_out=$(GEN_DIR)/go \
		--connect-go_opt=paths=source_relative \
		$(PROTO_DIR)/pm/v1/*.proto

inject-tags:
	protoc-go-inject-tag -input="$(GEN_DIR)/go/pm/v1/*.pb.go"

generate-ts:
	npx @bufbuild/buf generate

clean:
	rm -rf $(GEN_DIR)
