.PHONY: generate generate-go clean install-tools

# Proto source directory
PROTO_DIR := proto
# Generated output directory
GEN_DIR := gen

install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest
	go install github.com/favadi/protoc-go-inject-tag@latest

generate: generate-go inject-tags

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

clean:
	rm -rf $(GEN_DIR)
