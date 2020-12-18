// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: rpc.proto

package rpc

import (
	fmt "fmt"
	math "math"
	math_bits "math/bits"

	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	golang_proto "github.com/golang/protobuf/proto"
	validator "github.com/certikfoundation/burrow/acm/validator"
	bcm "github.com/certikfoundation/burrow/bcm"
	github_com_hyperledger_burrow_binary "github.com/certikfoundation/burrow/binary"
	tendermint "github.com/certikfoundation/burrow/consensus/tendermint"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = golang_proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type ResultStatus struct {
	ChainID       string                                        `protobuf:"bytes,1,opt,name=ChainID,proto3" json:"ChainID,omitempty"`
	RunID         string                                        `protobuf:"bytes,2,opt,name=RunID,proto3" json:"RunID,omitempty"`
	BurrowVersion string                                        `protobuf:"bytes,3,opt,name=BurrowVersion,proto3" json:"BurrowVersion,omitempty"`
	GenesisHash   github_com_hyperledger_burrow_binary.HexBytes `protobuf:"bytes,4,opt,name=GenesisHash,proto3,customtype=github.com/certikfoundation/burrow/binary.HexBytes" json:"GenesisHash"`
	NodeInfo      *tendermint.NodeInfo                          `protobuf:"bytes,5,opt,name=NodeInfo,proto3" json:"NodeInfo,omitempty"`
	SyncInfo      *bcm.SyncInfo                                 `protobuf:"bytes,6,opt,name=SyncInfo,proto3" json:"SyncInfo,omitempty"`
	// When catching up in fast sync
	CatchingUp           bool                 `protobuf:"varint,8,opt,name=CatchingUp,proto3" json:""`
	ValidatorInfo        *validator.Validator `protobuf:"bytes,7,opt,name=ValidatorInfo,proto3" json:"ValidatorInfo,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *ResultStatus) Reset()         { *m = ResultStatus{} }
func (m *ResultStatus) String() string { return proto.CompactTextString(m) }
func (*ResultStatus) ProtoMessage()    {}
func (*ResultStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_77a6da22d6a3feb1, []int{0}
}
func (m *ResultStatus) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResultStatus.Unmarshal(m, b)
}
func (m *ResultStatus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResultStatus.Marshal(b, m, deterministic)
}
func (m *ResultStatus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResultStatus.Merge(m, src)
}
func (m *ResultStatus) XXX_Size() int {
	return xxx_messageInfo_ResultStatus.Size(m)
}
func (m *ResultStatus) XXX_DiscardUnknown() {
	xxx_messageInfo_ResultStatus.DiscardUnknown(m)
}

var xxx_messageInfo_ResultStatus proto.InternalMessageInfo

func (m *ResultStatus) GetChainID() string {
	if m != nil {
		return m.ChainID
	}
	return ""
}

func (m *ResultStatus) GetRunID() string {
	if m != nil {
		return m.RunID
	}
	return ""
}

func (m *ResultStatus) GetBurrowVersion() string {
	if m != nil {
		return m.BurrowVersion
	}
	return ""
}

func (m *ResultStatus) GetNodeInfo() *tendermint.NodeInfo {
	if m != nil {
		return m.NodeInfo
	}
	return nil
}

func (m *ResultStatus) GetSyncInfo() *bcm.SyncInfo {
	if m != nil {
		return m.SyncInfo
	}
	return nil
}

func (m *ResultStatus) GetCatchingUp() bool {
	if m != nil {
		return m.CatchingUp
	}
	return false
}

func (m *ResultStatus) GetValidatorInfo() *validator.Validator {
	if m != nil {
		return m.ValidatorInfo
	}
	return nil
}

func (*ResultStatus) XXX_MessageName() string {
	return "rpc.ResultStatus"
}
func init() {
	proto.RegisterType((*ResultStatus)(nil), "rpc.ResultStatus")
	golang_proto.RegisterType((*ResultStatus)(nil), "rpc.ResultStatus")
}

func init() { proto.RegisterFile("rpc.proto", fileDescriptor_77a6da22d6a3feb1) }
func init() { golang_proto.RegisterFile("rpc.proto", fileDescriptor_77a6da22d6a3feb1) }

var fileDescriptor_77a6da22d6a3feb1 = []byte{
	// 364 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x91, 0xbd, 0x6e, 0xe2, 0x40,
	0x14, 0x85, 0x19, 0x7e, 0xcd, 0x00, 0xda, 0xd5, 0x88, 0xc2, 0xa2, 0x30, 0xde, 0x15, 0x85, 0xb7,
	0x58, 0x7b, 0xb5, 0x68, 0x9b, 0x2d, 0xcd, 0x4a, 0x0b, 0x4d, 0x8a, 0x41, 0x21, 0x52, 0x3a, 0xff,
	0x0c, 0xf6, 0x48, 0x30, 0x63, 0x8d, 0xc7, 0x49, 0xfc, 0x76, 0x29, 0x79, 0x84, 0x28, 0x05, 0x8a,
	0xa0, 0xcb, 0x33, 0xa4, 0x88, 0x18, 0x30, 0x31, 0x4d, 0xba, 0x7b, 0xbe, 0x73, 0xef, 0x91, 0x7d,
	0x06, 0xb6, 0x45, 0x12, 0xd8, 0x89, 0xe0, 0x92, 0xa3, 0x9a, 0x48, 0x82, 0xc1, 0xcf, 0x88, 0xca,
	0x38, 0xf3, 0xed, 0x80, 0xaf, 0x9d, 0x88, 0x47, 0xdc, 0x51, 0x9e, 0x9f, 0x2d, 0x95, 0x52, 0x42,
	0x4d, 0xc7, 0x9b, 0xc1, 0x57, 0x49, 0x58, 0x48, 0xc4, 0x9a, 0x32, 0x79, 0x22, 0x5f, 0xee, 0xbc,
	0x15, 0x0d, 0x3d, 0xc9, 0xc5, 0x09, 0xb4, 0xfd, 0x60, 0x7d, 0x1c, 0xbf, 0xbf, 0x55, 0x61, 0x17,
	0x93, 0x34, 0x5b, 0xc9, 0xb9, 0xf4, 0x64, 0x96, 0x22, 0x1d, 0xb6, 0x26, 0xb1, 0x47, 0xd9, 0xec,
	0x9f, 0x0e, 0x4c, 0x60, 0xb5, 0x71, 0x21, 0x51, 0x1f, 0x36, 0x70, 0x76, 0xe0, 0x55, 0xc5, 0x8f,
	0x02, 0x8d, 0x60, 0xcf, 0xcd, 0x84, 0xe0, 0xf7, 0x0b, 0x22, 0x52, 0xca, 0x99, 0x5e, 0x53, 0xee,
	0x25, 0x44, 0x37, 0xb0, 0xf3, 0x9f, 0x30, 0x92, 0xd2, 0x74, 0xea, 0xa5, 0xb1, 0x5e, 0x37, 0x81,
	0xd5, 0x75, 0xff, 0x6c, 0xb6, 0xc3, 0xca, 0xf3, 0x76, 0x58, 0xfe, 0xc1, 0x38, 0x4f, 0x88, 0x58,
	0x91, 0x30, 0x22, 0xc2, 0xf1, 0x55, 0x84, 0xe3, 0x53, 0xe6, 0x89, 0xdc, 0x9e, 0x92, 0x07, 0x37,
	0x97, 0x24, 0xc5, 0xe5, 0x24, 0xf4, 0x0b, 0x6a, 0x57, 0x3c, 0x24, 0x33, 0xb6, 0xe4, 0x7a, 0xc3,
	0x04, 0x56, 0xe7, 0x77, 0xdf, 0x2e, 0x15, 0x50, 0x78, 0xf8, 0xbc, 0x85, 0x7e, 0x40, 0x6d, 0x9e,
	0xb3, 0x40, 0x5d, 0x34, 0xd5, 0x45, 0xcf, 0x3e, 0xf4, 0x51, 0x40, 0x7c, 0xb6, 0xd1, 0x08, 0xc2,
	0x89, 0x27, 0x83, 0x98, 0xb2, 0xe8, 0x3a, 0xd1, 0x35, 0x13, 0x58, 0x9a, 0x5b, 0x7f, 0xdd, 0x0e,
	0x2b, 0xb8, 0xc4, 0xd1, 0x5f, 0xd8, 0x5b, 0x14, 0x05, 0xab, 0xd4, 0xd6, 0xe9, 0x3b, 0x3e, 0x6a,
	0x3f, 0xfb, 0xf8, 0x72, 0xd5, 0x1d, 0x3f, 0xed, 0x0c, 0xf0, 0xb2, 0x33, 0xc0, 0xe3, 0xde, 0x00,
	0x9b, 0xbd, 0x01, 0x6e, 0xbf, 0x7d, 0x5e, 0x86, 0x48, 0x02, 0xbf, 0xa9, 0x9e, 0x6e, 0xfc, 0x1e,
	0x00, 0x00, 0xff, 0xff, 0xd7, 0x87, 0x65, 0xef, 0x29, 0x02, 0x00, 0x00,
}

func (m *ResultStatus) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ChainID)
	if l > 0 {
		n += 1 + l + sovRpc(uint64(l))
	}
	l = len(m.RunID)
	if l > 0 {
		n += 1 + l + sovRpc(uint64(l))
	}
	l = len(m.BurrowVersion)
	if l > 0 {
		n += 1 + l + sovRpc(uint64(l))
	}
	l = m.GenesisHash.Size()
	n += 1 + l + sovRpc(uint64(l))
	if m.NodeInfo != nil {
		l = m.NodeInfo.Size()
		n += 1 + l + sovRpc(uint64(l))
	}
	if m.SyncInfo != nil {
		l = m.SyncInfo.Size()
		n += 1 + l + sovRpc(uint64(l))
	}
	if m.CatchingUp {
		n += 2
	}
	if m.ValidatorInfo != nil {
		l = m.ValidatorInfo.Size()
		n += 1 + l + sovRpc(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovRpc(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozRpc(x uint64) (n int) {
	return sovRpc(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
