.PHONY: generate generate-go generate-ts gofmt-gen clean install-tools

# Proto source directory
PROTO_DIR := proto
# Generated output directory
GEN_DIR := gen

install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest
	go install github.com/favadi/protoc-go-inject-tag@latest

# NOT prerequisites: make may satisfy those in any order, and concurrently
# under -j. This pipeline is strictly ordered — protoc writes the files,
# inject-tags rewrites their struct tags, gofmt cleans up after inject-tags —
# so the stages are invoked in sequence instead.
generate:
	$(MAKE) generate-go
	$(MAKE) inject-tags
	$(MAKE) gofmt-gen
	$(MAKE) generate-ts

# protoc-go-inject-tag rewrites struct tags but does NOT re-run gofmt
# afterwards, so its output can leave the generated .pb.go files with
# multi-field struct alignment that gofmt -l flags. Run gofmt -w over
# the gen directory once at the end of the Go pipeline to keep the
# committed gen files clean against `gofmt -l ./...`.
gofmt-gen:
	gofmt -w $(GEN_DIR)/go

# protoc writes outputs; it never deletes outputs whose INPUT is gone. Removing a
# .proto therefore leaves an orphaned .pb.go behind — and because a .pb.go
# registers its descriptors at init, the deleted service stays live at runtime
# and in protoregistry while every drift check (`git diff` on gen/) reports
# clean. Spec 41 hit exactly this: deleting internal.proto and gateway_auth.proto
# left four orphans that had to be removed by hand.
#
# So the generated directories are emptied before regeneration. Scoped to the
# pm/v1 output dirs rather than $(GEN_DIR) so nothing else under gen/ is at risk.
generate-go:
	@rm -f $(GEN_DIR)/go/pm/v1/*.pb.go $(GEN_DIR)/go/pm/v1/pmv1connect/*.connect.go
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

# Same orphan problem as generate-go: buf writes outputs and leaves behind any
# whose .proto input was deleted, and gen/ts is archived directly into the npm
# release, so a stale *_pb.ts ships to consumers as a live export.
generate-ts:
	@rm -f $(GEN_DIR)/ts/pm/v1/*_pb.ts
	npx @bufbuild/buf generate

clean:
	rm -rf $(GEN_DIR)
