package images

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protowire"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	machineSocketPath = "/system/run/machined/machine.sock"
	roleMdKey         = "talos-role"
	readerRole        = "os:reader"
	labelVerified     = "talos.dev/verified"
)

// Protobuf API definition we are going to call:
//
//	// Verify an image signature.
//	rpc Verify(ImageServiceVerifyRequest) returns (ImageServiceVerifyResponse);
//
// message ImageServiceVerifyRequest {
//
//	// Image reference to verify.
//	string image_ref = 1;
//	// Authentication credentials for the registry (if needed).
//	ImageServiceCredentials credentials = 2;
//
// }
//
// message ImageServiceCredentials {
//
//	string host = 1;
//	string username = 2;
//	string password = 3;
//
// }
//
// message ImageServiceVerifyResponse {
//
//	bool verified = 1;
//	string message = 2;
//	string digested_image_ref = 3;
//
// }

// rawBytesCodec is a gRPC codec that passes []byte through without re-marshaling,
// allowing us to use protowire-encoded bytes directly.
type rawBytesCodec struct{}

func (rawBytesCodec) Name() string { return "proto" }

func (rawBytesCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("rawBytesCodec: expected []byte, got %T", v)
	}

	return b, nil
}

func (rawBytesCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawBytesCodec: expected *[]byte, got %T", v)
	}

	*b = data

	return nil
}

var talosClient = sync.OnceValue(func() *grpc.ClientConn {
	cli, err := grpc.NewClient("unix:///"+machineSocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithNoProxy(),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create gRPC client for Talos machine API: %v", err))
	}

	return cli
})

func (c *CRIImageService) talosVerifyImage(ctx context.Context, ref string, authConfig *runtime.AuthConfig, labels map[string]string) (string, error) {
	cli := talosClient()

	ctx = metadata.NewOutgoingContext(ctx, metadata.MD{
		roleMdKey: []string{readerRole},
	})

	// decode auth config into ImageServiceCredentials:
	var (
		host string
		user string
		pass string
	)

	if authConfig != nil && authConfig.ServerAddress != "" {
		u, err := url.Parse(authConfig.ServerAddress)
		if err == nil {
			host = u.Host

			user, pass, err = ParseAuth(authConfig, host)
			if err != nil {
				return "", fmt.Errorf("failed to parse auth config: %w", err)
			}
		}
	}

	// Encode ImageServiceVerifyRequest using protowire:
	//   field 1 (string): image_ref
	var reqBuf []byte
	reqBuf = protowire.AppendTag(reqBuf, 1, protowire.BytesType)
	reqBuf = protowire.AppendString(reqBuf, ref)

	//   field 2 (message): credentials
	if host != "" || user != "" || pass != "" {
		var credBuf []byte

		if host != "" {
			credBuf = protowire.AppendTag(credBuf, 1, protowire.BytesType)
			credBuf = protowire.AppendString(credBuf, host)
		}

		if user != "" {
			credBuf = protowire.AppendTag(credBuf, 2, protowire.BytesType)
			credBuf = protowire.AppendString(credBuf, user)
		}

		if pass != "" {
			credBuf = protowire.AppendTag(credBuf, 3, protowire.BytesType)
			credBuf = protowire.AppendString(credBuf, pass)
		}

		reqBuf = protowire.AppendTag(reqBuf, 2, protowire.BytesType)
		reqBuf = protowire.AppendBytes(reqBuf, credBuf)
	}

	var respBuf []byte

	err := cli.Invoke(
		ctx,
		"/machine.ImageService/Verify",
		reqBuf,
		&respBuf,
		grpc.ForceCodec(rawBytesCodec{}),
	)
	if err != nil {
		return "", fmt.Errorf("failed to verify: %w", err)
	}

	// Decode ImageServiceVerifyResponse:
	//   field 1 (bool/varint): verified
	//   field 2 (string):      message
	//   field 3 (string):      digested_image_ref
	var (
		verified         bool
		message          string
		digestedImageRef string
	)

	for len(respBuf) > 0 {
		num, typ, n := protowire.ConsumeTag(respBuf)
		if n < 0 {
			return "", fmt.Errorf("failed to parse response tag: %w", protowire.ParseError(n))
		}

		respBuf = respBuf[n:]

		switch {
		case num == 1 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(respBuf)
			if n < 0 {
				return "", fmt.Errorf("failed to parse verified field: %w", protowire.ParseError(n))
			}

			verified = v != 0
			respBuf = respBuf[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(respBuf)
			if n < 0 {
				return "", fmt.Errorf("failed to parse message field: %w", protowire.ParseError(n))
			}

			message = v
			respBuf = respBuf[n:]
		case num == 3 && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(respBuf)
			if n < 0 {
				return "", fmt.Errorf("failed to parse digested_image_ref field: %w", protowire.ParseError(n))
			}

			digestedImageRef = v
			respBuf = respBuf[n:]
		default:
			// Skip unknown or unneeded fields.
			n := protowire.ConsumeFieldValue(num, typ, respBuf)
			if n < 0 {
				return "", fmt.Errorf("failed to skip field %d: %w", num, protowire.ParseError(n))
			}

			respBuf = respBuf[n:]
		}
	}

	if !verified {
		return "", nil
	}

	labels[labelVerified] = message

	return digestedImageRef, nil
}
