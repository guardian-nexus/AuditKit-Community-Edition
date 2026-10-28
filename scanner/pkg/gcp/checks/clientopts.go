package checks

import "google.golang.org/api/option"

// RESTTestOptions and GRPCTestOptions are appended to every Google client the
// scanner or a check creates. Both are empty in production. The denial test
// sets them to route every request to a fake that refuses it, which is the only
// way to see what each check reports when it cannot read the project: several
// checks build their own clients, so injecting at the scanner alone is not
// enough. REST and gRPC clients take different, incompatible options.
var (
	RESTTestOptions []option.ClientOption
	GRPCTestOptions []option.ClientOption
)

// RESTOptions returns opts plus any test options, for a REST (JSON over HTTP) client.
func RESTOptions(opts ...option.ClientOption) []option.ClientOption {
	return append(opts, RESTTestOptions...)
}

// GRPCOptions returns opts plus any test options, for a gRPC client.
func GRPCOptions(opts ...option.ClientOption) []option.ClientOption {
	return append(opts, GRPCTestOptions...)
}
