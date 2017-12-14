// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: health.proto

package grpc

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

import context "golang.org/x/net/context"
import grpc1 "google.golang.org/grpc"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type HealthCheckResponse_ServingStatus int32

const (
	HealthCheckResponse_UNKNOWN     HealthCheckResponse_ServingStatus = 0
	HealthCheckResponse_SERVING     HealthCheckResponse_ServingStatus = 1
	HealthCheckResponse_NOT_SERVING HealthCheckResponse_ServingStatus = 2
)

var HealthCheckResponse_ServingStatus_name = map[int32]string{
	0: "UNKNOWN",
	1: "SERVING",
	2: "NOT_SERVING",
}
var HealthCheckResponse_ServingStatus_value = map[string]int32{
	"UNKNOWN":     0,
	"SERVING":     1,
	"NOT_SERVING": 2,
}

func (x HealthCheckResponse_ServingStatus) String() string {
	return proto.EnumName(HealthCheckResponse_ServingStatus_name, int32(x))
}
func (HealthCheckResponse_ServingStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptorHealth, []int{1, 0}
}

type CheckRequest struct {
	Service string `protobuf:"bytes,1,opt,name=service,proto3" json:"service,omitempty"`
}

func (m *CheckRequest) Reset()                    { *m = CheckRequest{} }
func (m *CheckRequest) String() string            { return proto.CompactTextString(m) }
func (*CheckRequest) ProtoMessage()               {}
func (*CheckRequest) Descriptor() ([]byte, []int) { return fileDescriptorHealth, []int{0} }

func (m *CheckRequest) GetService() string {
	if m != nil {
		return m.Service
	}
	return ""
}

type HealthCheckResponse struct {
	Status HealthCheckResponse_ServingStatus `protobuf:"varint,1,opt,name=status,proto3,enum=grpc.HealthCheckResponse_ServingStatus" json:"status,omitempty"`
}

func (m *HealthCheckResponse) Reset()                    { *m = HealthCheckResponse{} }
func (m *HealthCheckResponse) String() string            { return proto.CompactTextString(m) }
func (*HealthCheckResponse) ProtoMessage()               {}
func (*HealthCheckResponse) Descriptor() ([]byte, []int) { return fileDescriptorHealth, []int{1} }

func (m *HealthCheckResponse) GetStatus() HealthCheckResponse_ServingStatus {
	if m != nil {
		return m.Status
	}
	return HealthCheckResponse_UNKNOWN
}

type VersionCheckResponse struct {
	GrpcVersion  string `protobuf:"bytes,1,opt,name=grpc_version,json=grpcVersion,proto3" json:"grpc_version,omitempty"`
	AgentVersion string `protobuf:"bytes,2,opt,name=agent_version,json=agentVersion,proto3" json:"agent_version,omitempty"`
}

func (m *VersionCheckResponse) Reset()                    { *m = VersionCheckResponse{} }
func (m *VersionCheckResponse) String() string            { return proto.CompactTextString(m) }
func (*VersionCheckResponse) ProtoMessage()               {}
func (*VersionCheckResponse) Descriptor() ([]byte, []int) { return fileDescriptorHealth, []int{2} }

func (m *VersionCheckResponse) GetGrpcVersion() string {
	if m != nil {
		return m.GrpcVersion
	}
	return ""
}

func (m *VersionCheckResponse) GetAgentVersion() string {
	if m != nil {
		return m.AgentVersion
	}
	return ""
}

func init() {
	proto.RegisterType((*CheckRequest)(nil), "grpc.CheckRequest")
	proto.RegisterType((*HealthCheckResponse)(nil), "grpc.HealthCheckResponse")
	proto.RegisterType((*VersionCheckResponse)(nil), "grpc.VersionCheckResponse")
	proto.RegisterEnum("grpc.HealthCheckResponse_ServingStatus", HealthCheckResponse_ServingStatus_name, HealthCheckResponse_ServingStatus_value)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc1.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc1.SupportPackageIsVersion4

// Client API for Health service

type HealthClient interface {
	Check(ctx context.Context, in *CheckRequest, opts ...grpc1.CallOption) (*HealthCheckResponse, error)
	Version(ctx context.Context, in *CheckRequest, opts ...grpc1.CallOption) (*VersionCheckResponse, error)
}

type healthClient struct {
	cc *grpc1.ClientConn
}

func NewHealthClient(cc *grpc1.ClientConn) HealthClient {
	return &healthClient{cc}
}

func (c *healthClient) Check(ctx context.Context, in *CheckRequest, opts ...grpc1.CallOption) (*HealthCheckResponse, error) {
	out := new(HealthCheckResponse)
	err := grpc1.Invoke(ctx, "/grpc.Health/Check", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *healthClient) Version(ctx context.Context, in *CheckRequest, opts ...grpc1.CallOption) (*VersionCheckResponse, error) {
	out := new(VersionCheckResponse)
	err := grpc1.Invoke(ctx, "/grpc.Health/Version", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Health service

type HealthServer interface {
	Check(context.Context, *CheckRequest) (*HealthCheckResponse, error)
	Version(context.Context, *CheckRequest) (*VersionCheckResponse, error)
}

func RegisterHealthServer(s *grpc1.Server, srv HealthServer) {
	s.RegisterService(&_Health_serviceDesc, srv)
}

func _Health_Check_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc1.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HealthServer).Check(ctx, in)
	}
	info := &grpc1.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.Health/Check",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HealthServer).Check(ctx, req.(*CheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Health_Version_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc1.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HealthServer).Version(ctx, in)
	}
	info := &grpc1.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.Health/Version",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HealthServer).Version(ctx, req.(*CheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Health_serviceDesc = grpc1.ServiceDesc{
	ServiceName: "grpc.Health",
	HandlerType: (*HealthServer)(nil),
	Methods: []grpc1.MethodDesc{
		{
			MethodName: "Check",
			Handler:    _Health_Check_Handler,
		},
		{
			MethodName: "Version",
			Handler:    _Health_Version_Handler,
		},
	},
	Streams:  []grpc1.StreamDesc{},
	Metadata: "health.proto",
}

func init() { proto.RegisterFile("health.proto", fileDescriptorHealth) }

var fileDescriptorHealth = []byte{
	// 261 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0xc9, 0x48, 0x4d, 0xcc,
	0x29, 0xc9, 0xd0, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x49, 0x2f, 0x2a, 0x48, 0x56, 0xd2,
	0xe0, 0xe2, 0x71, 0xce, 0x48, 0x4d, 0xce, 0x0e, 0x4a, 0x2d, 0x2c, 0x4d, 0x2d, 0x2e, 0x11, 0x92,
	0xe0, 0x62, 0x2f, 0x4e, 0x2d, 0x2a, 0xcb, 0x4c, 0x4e, 0x95, 0x60, 0x54, 0x60, 0xd4, 0xe0, 0x0c,
	0x82, 0x71, 0x95, 0x26, 0x31, 0x72, 0x09, 0x7b, 0x80, 0x0d, 0x80, 0x6a, 0x28, 0x2e, 0xc8, 0xcf,
	0x2b, 0x4e, 0x15, 0xb2, 0xe7, 0x62, 0x2b, 0x2e, 0x49, 0x2c, 0x29, 0x2d, 0x06, 0x6b, 0xe0, 0x33,
	0x52, 0xd7, 0x03, 0x19, 0xac, 0x87, 0x45, 0xa9, 0x5e, 0x30, 0xc8, 0xa8, 0xbc, 0xf4, 0x60, 0xb0,
	0xf2, 0x20, 0xa8, 0x36, 0x25, 0x2b, 0x2e, 0x5e, 0x14, 0x09, 0x21, 0x6e, 0x2e, 0xf6, 0x50, 0x3f,
	0x6f, 0x3f, 0xff, 0x70, 0x3f, 0x01, 0x06, 0x10, 0x27, 0xd8, 0x35, 0x28, 0xcc, 0xd3, 0xcf, 0x5d,
	0x80, 0x51, 0x88, 0x9f, 0x8b, 0xdb, 0xcf, 0x3f, 0x24, 0x1e, 0x26, 0xc0, 0xa4, 0x14, 0xc7, 0x25,
	0x12, 0x96, 0x5a, 0x54, 0x9c, 0x99, 0x9f, 0x87, 0xea, 0x28, 0x45, 0x2e, 0x1e, 0x90, 0x2b, 0xe2,
	0xcb, 0x20, 0x92, 0x50, 0xbf, 0x70, 0x83, 0xc4, 0xa0, 0xea, 0x85, 0x94, 0xb9, 0x78, 0x13, 0xd3,
	0x53, 0xf3, 0x4a, 0xe0, 0x6a, 0x98, 0xc0, 0x6a, 0x78, 0xc0, 0x82, 0x50, 0x45, 0x46, 0xd5, 0x5c,
	0x6c, 0x10, 0x8f, 0x08, 0x99, 0x71, 0xb1, 0x82, 0xad, 0x10, 0x12, 0x82, 0xf8, 0x0f, 0x39, 0xd4,
	0xa4, 0x24, 0x71, 0xfa, 0x59, 0xc8, 0x92, 0x8b, 0x1d, 0x66, 0x23, 0x36, 0x9d, 0x52, 0x10, 0x31,
	0x6c, 0x9e, 0x48, 0x62, 0x03, 0x47, 0x94, 0x31, 0x20, 0x00, 0x00, 0xff, 0xff, 0x12, 0xcd, 0xb7,
	0x8b, 0xb8, 0x01, 0x00, 0x00,
}
