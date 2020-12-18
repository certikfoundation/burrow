// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: dump.proto

package dump

import (
	fmt "fmt"
	io "io"
	math "math"
	math_bits "math/bits"
	time "time"

	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	github_com_gogo_protobuf_types "github.com/gogo/protobuf/types"
	golang_proto "github.com/golang/protobuf/proto"
	_ "github.com/golang/protobuf/ptypes/timestamp"
	acm "github.com/certikfoundation/burrow/acm"
	github_com_hyperledger_burrow_binary "github.com/certikfoundation/burrow/binary"
	github_com_hyperledger_burrow_crypto "github.com/certikfoundation/burrow/crypto"
	exec "github.com/certikfoundation/burrow/execution/exec"
	names "github.com/certikfoundation/burrow/execution/names"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = golang_proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Storage struct {
	Key                  github_com_hyperledger_burrow_binary.Word256  `protobuf:"bytes,1,opt,name=Key,proto3,customtype=github.com/certikfoundation/burrow/binary.Word256" json:"Key"`
	Value                github_com_hyperledger_burrow_binary.HexBytes `protobuf:"bytes,2,opt,name=Value,proto3,customtype=github.com/certikfoundation/burrow/binary.HexBytes" json:"Value"`
	XXX_NoUnkeyedLiteral struct{}                                      `json:"-"`
	XXX_unrecognized     []byte                                        `json:"-"`
	XXX_sizecache        int32                                         `json:"-"`
}

func (m *Storage) Reset()         { *m = Storage{} }
func (m *Storage) String() string { return proto.CompactTextString(m) }
func (*Storage) ProtoMessage()    {}
func (*Storage) Descriptor() ([]byte, []int) {
	return fileDescriptor_58418148159c29a6, []int{0}
}
func (m *Storage) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Storage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *Storage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Storage.Merge(m, src)
}
func (m *Storage) XXX_Size() int {
	return m.Size()
}
func (m *Storage) XXX_DiscardUnknown() {
	xxx_messageInfo_Storage.DiscardUnknown(m)
}

var xxx_messageInfo_Storage proto.InternalMessageInfo

func (*Storage) XXX_MessageName() string {
	return "dump.Storage"
}

type AccountStorage struct {
	Address              github_com_hyperledger_burrow_crypto.Address `protobuf:"bytes,1,opt,name=Address,proto3,customtype=github.com/certikfoundation/burrow/crypto.Address" json:"Address"`
	Storage              []*Storage                                   `protobuf:"bytes,2,rep,name=Storage,proto3" json:"Storage,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                     `json:"-"`
	XXX_unrecognized     []byte                                       `json:"-"`
	XXX_sizecache        int32                                        `json:"-"`
}

func (m *AccountStorage) Reset()         { *m = AccountStorage{} }
func (m *AccountStorage) String() string { return proto.CompactTextString(m) }
func (*AccountStorage) ProtoMessage()    {}
func (*AccountStorage) Descriptor() ([]byte, []int) {
	return fileDescriptor_58418148159c29a6, []int{1}
}
func (m *AccountStorage) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AccountStorage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *AccountStorage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AccountStorage.Merge(m, src)
}
func (m *AccountStorage) XXX_Size() int {
	return m.Size()
}
func (m *AccountStorage) XXX_DiscardUnknown() {
	xxx_messageInfo_AccountStorage.DiscardUnknown(m)
}

var xxx_messageInfo_AccountStorage proto.InternalMessageInfo

func (m *AccountStorage) GetStorage() []*Storage {
	if m != nil {
		return m.Storage
	}
	return nil
}

func (*AccountStorage) XXX_MessageName() string {
	return "dump.AccountStorage"
}

type EVMEvent struct {
	// The original ChainID from for this event
	ChainID string `protobuf:"bytes,1,opt,name=ChainID,proto3" json:"ChainID,omitempty"`
	// The original index for this event
	Index uint64 `protobuf:"varint,4,opt,name=Index,proto3" json:"Index,omitempty"`
	// The original block time for this transaction
	Time time.Time `protobuf:"bytes,2,opt,name=Time,proto3,stdtime" json:"Time"`
	// The event itself
	Event                *exec.LogEvent `protobuf:"bytes,3,opt,name=Event,proto3" json:"Event,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *EVMEvent) Reset()         { *m = EVMEvent{} }
func (m *EVMEvent) String() string { return proto.CompactTextString(m) }
func (*EVMEvent) ProtoMessage()    {}
func (*EVMEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_58418148159c29a6, []int{2}
}
func (m *EVMEvent) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *EVMEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *EVMEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EVMEvent.Merge(m, src)
}
func (m *EVMEvent) XXX_Size() int {
	return m.Size()
}
func (m *EVMEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_EVMEvent.DiscardUnknown(m)
}

var xxx_messageInfo_EVMEvent proto.InternalMessageInfo

func (m *EVMEvent) GetChainID() string {
	if m != nil {
		return m.ChainID
	}
	return ""
}

func (m *EVMEvent) GetIndex() uint64 {
	if m != nil {
		return m.Index
	}
	return 0
}

func (m *EVMEvent) GetTime() time.Time {
	if m != nil {
		return m.Time
	}
	return time.Time{}
}

func (m *EVMEvent) GetEvent() *exec.LogEvent {
	if m != nil {
		return m.Event
	}
	return nil
}

func (*EVMEvent) XXX_MessageName() string {
	return "dump.EVMEvent"
}

type Dump struct {
	Height               uint64          `protobuf:"varint,1,opt,name=Height,proto3" json:"Height,omitempty"`
	Account              *acm.Account    `protobuf:"bytes,2,opt,name=Account,proto3" json:"Account,omitempty"`
	AccountStorage       *AccountStorage `protobuf:"bytes,3,opt,name=AccountStorage,proto3" json:"AccountStorage,omitempty"`
	EVMEvent             *EVMEvent       `protobuf:"bytes,4,opt,name=EVMEvent,proto3" json:"EVMEvent,omitempty"`
	Name                 *names.Entry    `protobuf:"bytes,5,opt,name=Name,proto3" json:"Name,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *Dump) Reset()         { *m = Dump{} }
func (m *Dump) String() string { return proto.CompactTextString(m) }
func (*Dump) ProtoMessage()    {}
func (*Dump) Descriptor() ([]byte, []int) {
	return fileDescriptor_58418148159c29a6, []int{3}
}
func (m *Dump) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Dump) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *Dump) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Dump.Merge(m, src)
}
func (m *Dump) XXX_Size() int {
	return m.Size()
}
func (m *Dump) XXX_DiscardUnknown() {
	xxx_messageInfo_Dump.DiscardUnknown(m)
}

var xxx_messageInfo_Dump proto.InternalMessageInfo

func (m *Dump) GetHeight() uint64 {
	if m != nil {
		return m.Height
	}
	return 0
}

func (m *Dump) GetAccount() *acm.Account {
	if m != nil {
		return m.Account
	}
	return nil
}

func (m *Dump) GetAccountStorage() *AccountStorage {
	if m != nil {
		return m.AccountStorage
	}
	return nil
}

func (m *Dump) GetEVMEvent() *EVMEvent {
	if m != nil {
		return m.EVMEvent
	}
	return nil
}

func (m *Dump) GetName() *names.Entry {
	if m != nil {
		return m.Name
	}
	return nil
}

func (*Dump) XXX_MessageName() string {
	return "dump.Dump"
}
func init() {
	proto.RegisterType((*Storage)(nil), "dump.Storage")
	golang_proto.RegisterType((*Storage)(nil), "dump.Storage")
	proto.RegisterType((*AccountStorage)(nil), "dump.AccountStorage")
	golang_proto.RegisterType((*AccountStorage)(nil), "dump.AccountStorage")
	proto.RegisterType((*EVMEvent)(nil), "dump.EVMEvent")
	golang_proto.RegisterType((*EVMEvent)(nil), "dump.EVMEvent")
	proto.RegisterType((*Dump)(nil), "dump.Dump")
	golang_proto.RegisterType((*Dump)(nil), "dump.Dump")
}

func init() { proto.RegisterFile("dump.proto", fileDescriptor_58418148159c29a6) }
func init() { golang_proto.RegisterFile("dump.proto", fileDescriptor_58418148159c29a6) }

var fileDescriptor_58418148159c29a6 = []byte{
	// 493 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x52, 0x4d, 0x6f, 0xd3, 0x40,
	0x10, 0x65, 0x5b, 0xa7, 0x69, 0x37, 0xa5, 0x87, 0x55, 0x85, 0xac, 0x1c, 0x9c, 0xc8, 0x42, 0x10,
	0x21, 0xba, 0x91, 0x02, 0x45, 0x1c, 0x7a, 0x69, 0x68, 0x50, 0xab, 0x42, 0x0f, 0x4b, 0x55, 0x24,
	0x6e, 0xfe, 0x18, 0x1c, 0x4b, 0xb1, 0xd7, 0x5a, 0xaf, 0x21, 0xfe, 0x09, 0xdc, 0x38, 0x73, 0xe0,
	0xb7, 0x70, 0xcc, 0x11, 0x71, 0x42, 0x1c, 0x0a, 0x4a, 0xff, 0x08, 0xf2, 0x7e, 0x10, 0xe8, 0x01,
	0xc1, 0x6d, 0x66, 0x9e, 0xe7, 0xcd, 0xf3, 0x7b, 0x8b, 0x71, 0x5c, 0x65, 0x05, 0x2d, 0x04, 0x97,
	0x9c, 0x38, 0x4d, 0xdd, 0xdd, 0x4b, 0x52, 0x39, 0xad, 0x42, 0x1a, 0xf1, 0x6c, 0x98, 0xf0, 0x84,
	0x0f, 0x15, 0x18, 0x56, 0xaf, 0x55, 0xa7, 0x1a, 0x55, 0xe9, 0xa5, 0x6e, 0x2f, 0xe1, 0x3c, 0x99,
	0xc1, 0xea, 0x2b, 0x99, 0x66, 0x50, 0xca, 0xc0, 0xb2, 0x76, 0xb7, 0x82, 0x28, 0x33, 0x25, 0x86,
	0x39, 0x44, 0xa6, 0xee, 0xe4, 0x41, 0x06, 0xa5, 0x6e, 0xfc, 0x8f, 0x08, 0xb7, 0x5f, 0x48, 0x2e,
	0x82, 0x04, 0xc8, 0x53, 0xbc, 0x7e, 0x0a, 0xb5, 0x8b, 0xfa, 0x68, 0xb0, 0x3d, 0x7e, 0xb8, 0xb8,
	0xec, 0xdd, 0xf8, 0x76, 0xd9, 0xbb, 0xff, 0x9b, 0xa8, 0x69, 0x5d, 0x80, 0x98, 0x41, 0x9c, 0x80,
	0x18, 0x86, 0x95, 0x10, 0xfc, 0xed, 0x30, 0x4c, 0xf3, 0x40, 0xd4, 0xf4, 0x25, 0x17, 0xf1, 0x68,
	0xff, 0x11, 0x6b, 0x08, 0xc8, 0x29, 0x6e, 0x5d, 0x04, 0xb3, 0x0a, 0xdc, 0x35, 0xc5, 0xb4, 0x6f,
	0x98, 0xf6, 0xfe, 0x89, 0xe9, 0x18, 0xe6, 0xe3, 0x5a, 0x42, 0xc9, 0x34, 0x87, 0xff, 0x0e, 0xe1,
	0x9d, 0xc3, 0x28, 0xe2, 0x55, 0x2e, 0xad, 0xce, 0x33, 0xdc, 0x3e, 0x8c, 0x63, 0x01, 0x65, 0xf9,
	0x7f, 0x5a, 0x23, 0x51, 0x17, 0x92, 0x53, 0xb3, 0xcb, 0x2c, 0x09, 0xb9, 0xfb, 0xcb, 0x02, 0x77,
	0xad, 0xbf, 0x3e, 0xe8, 0x8c, 0x6e, 0x52, 0x95, 0x8d, 0x19, 0x32, 0x8b, 0xfa, 0x1f, 0x10, 0xde,
	0x9c, 0x5c, 0x3c, 0x9f, 0xbc, 0x81, 0x5c, 0x12, 0x17, 0xb7, 0x9f, 0x4c, 0x83, 0x34, 0x3f, 0x39,
	0x52, 0x2a, 0xb6, 0x98, 0x6d, 0xc9, 0x2e, 0x6e, 0x9d, 0xe4, 0x31, 0xcc, 0x5d, 0xa7, 0x8f, 0x06,
	0x0e, 0xd3, 0x0d, 0x79, 0x8c, 0x9d, 0xf3, 0x34, 0xd3, 0xa6, 0x74, 0x46, 0x5d, 0xaa, 0xd3, 0xa3,
	0x36, 0x3d, 0x7a, 0x6e, 0xd3, 0x1b, 0x6f, 0x36, 0xbf, 0xf3, 0xfe, 0x7b, 0x0f, 0x31, 0xb5, 0x41,
	0x6e, 0xe3, 0x96, 0x3a, 0xe9, 0xae, 0xab, 0xd5, 0x1d, 0xaa, 0xc2, 0x7c, 0xc6, 0x13, 0x35, 0x65,
	0x1a, 0xf4, 0xbf, 0x20, 0xec, 0x1c, 0x55, 0x59, 0x41, 0x6e, 0xe1, 0x8d, 0x63, 0x48, 0x93, 0xa9,
	0x54, 0xba, 0x1c, 0x66, 0x3a, 0x72, 0x07, 0xb7, 0x8d, 0x91, 0x46, 0xc3, 0x36, 0x6d, 0x1e, 0x88,
	0x99, 0x31, 0x0b, 0x92, 0x83, 0xeb, 0x86, 0x9b, 0xbb, 0xbb, 0xda, 0x95, 0x3f, 0x31, 0x76, 0x3d,
	0x9c, 0x7b, 0x2b, 0x8b, 0xd4, 0xff, 0x37, 0x7a, 0xd5, 0x9e, 0x9d, 0xb2, 0x95, 0x85, 0x7d, 0xec,
	0x9c, 0x05, 0x19, 0xb8, 0x2d, 0x23, 0x47, 0x3f, 0xcc, 0x49, 0x2e, 0x45, 0xcd, 0x14, 0x32, 0x3e,
	0x58, 0x2c, 0x3d, 0xf4, 0x79, 0xe9, 0xa1, 0xaf, 0x4b, 0x0f, 0xfd, 0x58, 0x7a, 0xe8, 0xd3, 0x95,
	0x87, 0x16, 0x57, 0x1e, 0x7a, 0xe5, 0xff, 0x3d, 0xeb, 0xe6, 0x64, 0xb8, 0xa1, 0xcc, 0x7d, 0xf0,
	0x33, 0x00, 0x00, 0xff, 0xff, 0x30, 0xe1, 0x0a, 0x94, 0x6b, 0x03, 0x00, 0x00,
}

func (m *Storage) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Storage) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Storage) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	{
		size := m.Value.Size()
		i -= size
		if _, err := m.Value.MarshalTo(dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintDump(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	{
		size := m.Key.Size()
		i -= size
		if _, err := m.Key.MarshalTo(dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintDump(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *AccountStorage) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AccountStorage) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AccountStorage) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Storage) > 0 {
		for iNdEx := len(m.Storage) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Storage[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintDump(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x12
		}
	}
	{
		size := m.Address.Size()
		i -= size
		if _, err := m.Address.MarshalTo(dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintDump(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *EVMEvent) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *EVMEvent) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *EVMEvent) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Index != 0 {
		i = encodeVarintDump(dAtA, i, uint64(m.Index))
		i--
		dAtA[i] = 0x20
	}
	if m.Event != nil {
		{
			size, err := m.Event.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintDump(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	n2, err2 := github_com_gogo_protobuf_types.StdTimeMarshalTo(m.Time, dAtA[i-github_com_gogo_protobuf_types.SizeOfStdTime(m.Time):])
	if err2 != nil {
		return 0, err2
	}
	i -= n2
	i = encodeVarintDump(dAtA, i, uint64(n2))
	i--
	dAtA[i] = 0x12
	if len(m.ChainID) > 0 {
		i -= len(m.ChainID)
		copy(dAtA[i:], m.ChainID)
		i = encodeVarintDump(dAtA, i, uint64(len(m.ChainID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Dump) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Dump) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Dump) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Name != nil {
		{
			size, err := m.Name.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintDump(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x2a
	}
	if m.EVMEvent != nil {
		{
			size, err := m.EVMEvent.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintDump(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x22
	}
	if m.AccountStorage != nil {
		{
			size, err := m.AccountStorage.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintDump(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.Account != nil {
		{
			size, err := m.Account.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintDump(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.Height != 0 {
		i = encodeVarintDump(dAtA, i, uint64(m.Height))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintDump(dAtA []byte, offset int, v uint64) int {
	offset -= sovDump(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Storage) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.Key.Size()
	n += 1 + l + sovDump(uint64(l))
	l = m.Value.Size()
	n += 1 + l + sovDump(uint64(l))
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *AccountStorage) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.Address.Size()
	n += 1 + l + sovDump(uint64(l))
	if len(m.Storage) > 0 {
		for _, e := range m.Storage {
			l = e.Size()
			n += 1 + l + sovDump(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *EVMEvent) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ChainID)
	if l > 0 {
		n += 1 + l + sovDump(uint64(l))
	}
	l = github_com_gogo_protobuf_types.SizeOfStdTime(m.Time)
	n += 1 + l + sovDump(uint64(l))
	if m.Event != nil {
		l = m.Event.Size()
		n += 1 + l + sovDump(uint64(l))
	}
	if m.Index != 0 {
		n += 1 + sovDump(uint64(m.Index))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *Dump) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Height != 0 {
		n += 1 + sovDump(uint64(m.Height))
	}
	if m.Account != nil {
		l = m.Account.Size()
		n += 1 + l + sovDump(uint64(l))
	}
	if m.AccountStorage != nil {
		l = m.AccountStorage.Size()
		n += 1 + l + sovDump(uint64(l))
	}
	if m.EVMEvent != nil {
		l = m.EVMEvent.Size()
		n += 1 + l + sovDump(uint64(l))
	}
	if m.Name != nil {
		l = m.Name.Size()
		n += 1 + l + sovDump(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovDump(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozDump(x uint64) (n int) {
	return sovDump(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Storage) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDump
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Storage: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Storage: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Key", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Key.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Value", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Value.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipDump(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthDump
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthDump
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *AccountStorage) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDump
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AccountStorage: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AccountStorage: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Address", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Address.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Storage", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Storage = append(m.Storage, &Storage{})
			if err := m.Storage[len(m.Storage)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipDump(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthDump
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthDump
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *EVMEvent) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDump
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: EVMEvent: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: EVMEvent: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ChainID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ChainID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Time", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := github_com_gogo_protobuf_types.StdTimeUnmarshal(&m.Time, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Event", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Event == nil {
				m.Event = &exec.LogEvent{}
			}
			if err := m.Event.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Index", wireType)
			}
			m.Index = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Index |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipDump(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthDump
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthDump
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Dump) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDump
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Dump: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Dump: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Height", wireType)
			}
			m.Height = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Height |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Account", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Account == nil {
				m.Account = &acm.Account{}
			}
			if err := m.Account.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AccountStorage", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.AccountStorage == nil {
				m.AccountStorage = &AccountStorage{}
			}
			if err := m.AccountStorage.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field EVMEvent", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.EVMEvent == nil {
				m.EVMEvent = &EVMEvent{}
			}
			if err := m.EVMEvent.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDump
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDump
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDump
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Name == nil {
				m.Name = &names.Entry{}
			}
			if err := m.Name.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipDump(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthDump
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthDump
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipDump(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowDump
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowDump
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowDump
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthDump
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupDump
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthDump
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthDump        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowDump          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupDump = fmt.Errorf("proto: unexpected end of group")
)
