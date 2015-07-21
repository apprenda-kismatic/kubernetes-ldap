// This file just generates the Go code from the protobufs.
package pb

//go:generate protoc --go_out=google/protobuf any.proto
//go:generate protoc --go_out=. token.proto --descriptor_set_out=token.descriptor.pb --include_imports

// An ugly hack because protoc-gen-go doesn't seem to handle the Any type correctly
// yet.
//go:generate sed -Eie 's_"google/protobuf"_"./google/protobuf"_' *.proto
