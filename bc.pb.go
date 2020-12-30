// Code generated by protoc-gen-go. DO NOT EDIT.
// source: bc.proto

package bcgo

import (
	cryptogo "aletheiaware.com/cryptogo"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Block struct {
	// Timestamp (nanoseconds) when the block was created.
	Timestamp uint64 `protobuf:"fixed64,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// Name of the channel.
	ChannelName string `protobuf:"bytes,2,opt,name=channel_name,json=channelName,proto3" json:"channel_name,omitempty"`
	// Length of chain in blocks (inclusive).
	Length uint64 `protobuf:"fixed64,3,opt,name=length,proto3" json:"length,omitempty"`
	// Hash of the previous block in the chain.
	Previous []byte `protobuf:"bytes,4,opt,name=previous,proto3" json:"previous,omitempty"`
	// Alias of the block miner's public key.
	Miner string `protobuf:"bytes,5,opt,name=miner,proto3" json:"miner,omitempty"`
	// The nonce mined to reach threshold.
	Nonce uint64 `protobuf:"fixed64,6,opt,name=nonce,proto3" json:"nonce,omitempty"`
	// The block's entries (list of hash/record pairs).
	Entry                []*BlockEntry `protobuf:"bytes,7,rep,name=entry,proto3" json:"entry,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *Block) Reset()         { *m = Block{} }
func (m *Block) String() string { return proto.CompactTextString(m) }
func (*Block) ProtoMessage()    {}
func (*Block) Descriptor() ([]byte, []int) {
	return fileDescriptor_99e2a20f8b284799, []int{0}
}

func (m *Block) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Block.Unmarshal(m, b)
}
func (m *Block) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Block.Marshal(b, m, deterministic)
}
func (m *Block) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Block.Merge(m, src)
}
func (m *Block) XXX_Size() int {
	return xxx_messageInfo_Block.Size(m)
}
func (m *Block) XXX_DiscardUnknown() {
	xxx_messageInfo_Block.DiscardUnknown(m)
}

var xxx_messageInfo_Block proto.InternalMessageInfo

func (m *Block) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *Block) GetChannelName() string {
	if m != nil {
		return m.ChannelName
	}
	return ""
}

func (m *Block) GetLength() uint64 {
	if m != nil {
		return m.Length
	}
	return 0
}

func (m *Block) GetPrevious() []byte {
	if m != nil {
		return m.Previous
	}
	return nil
}

func (m *Block) GetMiner() string {
	if m != nil {
		return m.Miner
	}
	return ""
}

func (m *Block) GetNonce() uint64 {
	if m != nil {
		return m.Nonce
	}
	return 0
}

func (m *Block) GetEntry() []*BlockEntry {
	if m != nil {
		return m.Entry
	}
	return nil
}

type BlockEntry struct {
	// Hash of the record.
	RecordHash           []byte   `protobuf:"bytes,1,opt,name=record_hash,json=recordHash,proto3" json:"record_hash,omitempty"`
	Record               *Record  `protobuf:"bytes,2,opt,name=record,proto3" json:"record,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BlockEntry) Reset()         { *m = BlockEntry{} }
func (m *BlockEntry) String() string { return proto.CompactTextString(m) }
func (*BlockEntry) ProtoMessage()    {}
func (*BlockEntry) Descriptor() ([]byte, []int) {
	return fileDescriptor_99e2a20f8b284799, []int{1}
}

func (m *BlockEntry) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BlockEntry.Unmarshal(m, b)
}
func (m *BlockEntry) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BlockEntry.Marshal(b, m, deterministic)
}
func (m *BlockEntry) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BlockEntry.Merge(m, src)
}
func (m *BlockEntry) XXX_Size() int {
	return xxx_messageInfo_BlockEntry.Size(m)
}
func (m *BlockEntry) XXX_DiscardUnknown() {
	xxx_messageInfo_BlockEntry.DiscardUnknown(m)
}

var xxx_messageInfo_BlockEntry proto.InternalMessageInfo

func (m *BlockEntry) GetRecordHash() []byte {
	if m != nil {
		return m.RecordHash
	}
	return nil
}

func (m *BlockEntry) GetRecord() *Record {
	if m != nil {
		return m.Record
	}
	return nil
}

type Record struct {
	// Timestamp (nanoseconds) when the record was created.
	Timestamp uint64 `protobuf:"fixed64,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// Alias of the record creator's public key.
	Creator string `protobuf:"bytes,2,opt,name=creator,proto3" json:"creator,omitempty"`
	// The list of accesses granted.
	Access []*Record_Access `protobuf:"bytes,3,rep,name=access,proto3" json:"access,omitempty"`
	// Holds record content, optionally encrypted with a secret key.
	Payload []byte `protobuf:"bytes,4,opt,name=payload,proto3" json:"payload,omitempty"`
	// The algorithm used to compress the payload.
	CompressionAlgorithm cryptogo.CompressionAlgorithm `protobuf:"varint,5,opt,name=compression_algorithm,json=compressionAlgorithm,proto3,enum=crypto.CompressionAlgorithm" json:"compression_algorithm,omitempty"`
	// The algorithm used to encrypt the payload.
	EncryptionAlgorithm cryptogo.EncryptionAlgorithm `protobuf:"varint,6,opt,name=encryption_algorithm,json=encryptionAlgorithm,proto3,enum=crypto.EncryptionAlgorithm" json:"encryption_algorithm,omitempty"`
	// Signature of payload (signed by the record creator's private key).
	Signature []byte `protobuf:"bytes,7,opt,name=signature,proto3" json:"signature,omitempty"`
	// The algorithm used to sign the payload.
	SignatureAlgorithm cryptogo.SignatureAlgorithm `protobuf:"varint,8,opt,name=signature_algorithm,json=signatureAlgorithm,proto3,enum=crypto.SignatureAlgorithm" json:"signature_algorithm,omitempty"`
	// References to previous records.
	Reference []*Reference `protobuf:"bytes,9,rep,name=reference,proto3" json:"reference,omitempty"`
	// Holds payload meta data.
	Meta                 map[string]string `protobuf:"bytes,10,rep,name=meta,proto3" json:"meta,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Record) Reset()         { *m = Record{} }
func (m *Record) String() string { return proto.CompactTextString(m) }
func (*Record) ProtoMessage()    {}
func (*Record) Descriptor() ([]byte, []int) {
	return fileDescriptor_99e2a20f8b284799, []int{2}
}

func (m *Record) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Record.Unmarshal(m, b)
}
func (m *Record) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Record.Marshal(b, m, deterministic)
}
func (m *Record) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Record.Merge(m, src)
}
func (m *Record) XXX_Size() int {
	return xxx_messageInfo_Record.Size(m)
}
func (m *Record) XXX_DiscardUnknown() {
	xxx_messageInfo_Record.DiscardUnknown(m)
}

var xxx_messageInfo_Record proto.InternalMessageInfo

func (m *Record) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *Record) GetCreator() string {
	if m != nil {
		return m.Creator
	}
	return ""
}

func (m *Record) GetAccess() []*Record_Access {
	if m != nil {
		return m.Access
	}
	return nil
}

func (m *Record) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *Record) GetCompressionAlgorithm() cryptogo.CompressionAlgorithm {
	if m != nil {
		return m.CompressionAlgorithm
	}
	return cryptogo.CompressionAlgorithm_UNKNOWN_COMPRESSION
}

func (m *Record) GetEncryptionAlgorithm() cryptogo.EncryptionAlgorithm {
	if m != nil {
		return m.EncryptionAlgorithm
	}
	return cryptogo.EncryptionAlgorithm_UNKNOWN_ENCRYPTION
}

func (m *Record) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func (m *Record) GetSignatureAlgorithm() cryptogo.SignatureAlgorithm {
	if m != nil {
		return m.SignatureAlgorithm
	}
	return cryptogo.SignatureAlgorithm_UNKNOWN_SIGNATURE
}

func (m *Record) GetReference() []*Reference {
	if m != nil {
		return m.Reference
	}
	return nil
}

func (m *Record) GetMeta() map[string]string {
	if m != nil {
		return m.Meta
	}
	return nil
}

type Record_Access struct {
	// Alias of the public key granted access, empty if public.
	Alias string `protobuf:"bytes,1,opt,name=alias,proto3" json:"alias,omitempty"`
	// The secret access key used to encrypt the payload.
	SecretKey []byte `protobuf:"bytes,2,opt,name=secret_key,json=secretKey,proto3" json:"secret_key,omitempty"`
	// If the alias is set, the secret key will be encrypted by the alias' public key.
	// The algorithm used to encrypt the secret key.
	EncryptionAlgorithm  cryptogo.EncryptionAlgorithm `protobuf:"varint,3,opt,name=encryption_algorithm,json=encryptionAlgorithm,proto3,enum=crypto.EncryptionAlgorithm" json:"encryption_algorithm,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *Record_Access) Reset()         { *m = Record_Access{} }
func (m *Record_Access) String() string { return proto.CompactTextString(m) }
func (*Record_Access) ProtoMessage()    {}
func (*Record_Access) Descriptor() ([]byte, []int) {
	return fileDescriptor_99e2a20f8b284799, []int{2, 0}
}

func (m *Record_Access) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Record_Access.Unmarshal(m, b)
}
func (m *Record_Access) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Record_Access.Marshal(b, m, deterministic)
}
func (m *Record_Access) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Record_Access.Merge(m, src)
}
func (m *Record_Access) XXX_Size() int {
	return xxx_messageInfo_Record_Access.Size(m)
}
func (m *Record_Access) XXX_DiscardUnknown() {
	xxx_messageInfo_Record_Access.DiscardUnknown(m)
}

var xxx_messageInfo_Record_Access proto.InternalMessageInfo

func (m *Record_Access) GetAlias() string {
	if m != nil {
		return m.Alias
	}
	return ""
}

func (m *Record_Access) GetSecretKey() []byte {
	if m != nil {
		return m.SecretKey
	}
	return nil
}

func (m *Record_Access) GetEncryptionAlgorithm() cryptogo.EncryptionAlgorithm {
	if m != nil {
		return m.EncryptionAlgorithm
	}
	return cryptogo.EncryptionAlgorithm_UNKNOWN_ENCRYPTION
}

type Reference struct {
	// Timestamp (nanoseconds) when the referenced item was created.
	Timestamp uint64 `protobuf:"fixed64,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// Name of the channel holding the referenced item.
	ChannelName string `protobuf:"bytes,2,opt,name=channel_name,json=channelName,proto3" json:"channel_name,omitempty"`
	// Hash of the block holding the referenced item.
	BlockHash []byte `protobuf:"bytes,3,opt,name=block_hash,json=blockHash,proto3" json:"block_hash,omitempty"`
	// Hash of the record holding the referenced item.
	RecordHash []byte `protobuf:"bytes,4,opt,name=record_hash,json=recordHash,proto3" json:"record_hash,omitempty"`
	// Index of block in chain holding the referenced item.
	Index                uint64   `protobuf:"fixed64,5,opt,name=index,proto3" json:"index,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Reference) Reset()         { *m = Reference{} }
func (m *Reference) String() string { return proto.CompactTextString(m) }
func (*Reference) ProtoMessage()    {}
func (*Reference) Descriptor() ([]byte, []int) {
	return fileDescriptor_99e2a20f8b284799, []int{3}
}

func (m *Reference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Reference.Unmarshal(m, b)
}
func (m *Reference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Reference.Marshal(b, m, deterministic)
}
func (m *Reference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Reference.Merge(m, src)
}
func (m *Reference) XXX_Size() int {
	return xxx_messageInfo_Reference.Size(m)
}
func (m *Reference) XXX_DiscardUnknown() {
	xxx_messageInfo_Reference.DiscardUnknown(m)
}

var xxx_messageInfo_Reference proto.InternalMessageInfo

func (m *Reference) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *Reference) GetChannelName() string {
	if m != nil {
		return m.ChannelName
	}
	return ""
}

func (m *Reference) GetBlockHash() []byte {
	if m != nil {
		return m.BlockHash
	}
	return nil
}

func (m *Reference) GetRecordHash() []byte {
	if m != nil {
		return m.RecordHash
	}
	return nil
}

func (m *Reference) GetIndex() uint64 {
	if m != nil {
		return m.Index
	}
	return 0
}

func init() {
	proto.RegisterType((*Block)(nil), "bc.Block")
	proto.RegisterType((*BlockEntry)(nil), "bc.BlockEntry")
	proto.RegisterType((*Record)(nil), "bc.Record")
	proto.RegisterMapType((map[string]string)(nil), "bc.Record.MetaEntry")
	proto.RegisterType((*Record_Access)(nil), "bc.Record.Access")
	proto.RegisterType((*Reference)(nil), "bc.Reference")
}

func init() { proto.RegisterFile("bc.proto", fileDescriptor_99e2a20f8b284799) }

var fileDescriptor_99e2a20f8b284799 = []byte{
	// 600 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x94, 0x51, 0x6f, 0xd3, 0x30,
	0x10, 0xc7, 0x95, 0x75, 0x4d, 0x97, 0x6b, 0x99, 0xc0, 0x2b, 0x28, 0x2a, 0x9b, 0x56, 0x2a, 0x1e,
	0x8a, 0x90, 0x32, 0x69, 0x3c, 0x80, 0x78, 0x41, 0xeb, 0x34, 0x09, 0x69, 0x63, 0x62, 0xe1, 0x01,
	0x89, 0x97, 0xca, 0xf1, 0x8e, 0x26, 0x5a, 0x12, 0x47, 0xb6, 0x3b, 0xe8, 0x87, 0xe0, 0x4b, 0xf0,
	0x15, 0xf8, 0x1e, 0x7c, 0x26, 0xe4, 0x73, 0xd2, 0x0c, 0x06, 0x42, 0x82, 0xb7, 0xfc, 0x7f, 0xbe,
	0xdc, 0x9d, 0xff, 0xf6, 0x19, 0xb6, 0x12, 0x11, 0x55, 0x4a, 0x1a, 0xc9, 0x36, 0x12, 0x31, 0x1a,
	0x08, 0xb5, 0xaa, 0x8c, 0x74, 0x64, 0xf2, 0xdd, 0x83, 0xee, 0x2c, 0x97, 0xe2, 0x8a, 0xed, 0x42,
	0x60, 0xb2, 0x02, 0xb5, 0xe1, 0x45, 0x15, 0x7a, 0x63, 0x6f, 0xea, 0xc7, 0x2d, 0x60, 0x8f, 0x60,
	0x20, 0x52, 0x5e, 0x96, 0x98, 0xcf, 0x4b, 0x5e, 0x60, 0xb8, 0x31, 0xf6, 0xa6, 0x41, 0xdc, 0xaf,
	0xd9, 0x39, 0x2f, 0x90, 0x3d, 0x00, 0x3f, 0xc7, 0x72, 0x61, 0xd2, 0xb0, 0x43, 0x7f, 0xd7, 0x8a,
	0x8d, 0x60, 0xab, 0x52, 0x78, 0x9d, 0xc9, 0xa5, 0x0e, 0x37, 0xc7, 0xde, 0x74, 0x10, 0xaf, 0x35,
	0x1b, 0x42, 0xb7, 0xc8, 0x4a, 0x54, 0x61, 0x97, 0xf2, 0x39, 0x61, 0x69, 0x29, 0x4b, 0x81, 0xa1,
	0x4f, 0x89, 0x9c, 0x60, 0x8f, 0xa1, 0x8b, 0xa5, 0x51, 0xab, 0xb0, 0x37, 0xee, 0x4c, 0xfb, 0x87,
	0xdb, 0x51, 0x22, 0x22, 0x6a, 0xfd, 0xc4, 0xd2, 0xd8, 0x2d, 0x4e, 0x2e, 0x00, 0x5a, 0xc8, 0xf6,
	0xa1, 0xaf, 0x50, 0x48, 0x75, 0x39, 0x4f, 0xb9, 0x4e, 0x69, 0x5b, 0x83, 0x18, 0x1c, 0x7a, 0xcd,
	0x75, 0xca, 0x26, 0xe0, 0x3b, 0x45, 0x3b, 0xea, 0x1f, 0x82, 0xcd, 0x1a, 0x13, 0x89, 0xeb, 0x95,
	0xc9, 0xb7, 0x2e, 0xf8, 0x0e, 0xfd, 0xc5, 0xa4, 0x10, 0x7a, 0x42, 0x21, 0x37, 0x52, 0xd5, 0xfe,
	0x34, 0x92, 0x3d, 0x01, 0x9f, 0x0b, 0x81, 0x5a, 0x87, 0x1d, 0x6a, 0xfe, 0x5e, 0x5b, 0x26, 0x3a,
	0xa2, 0x85, 0xb8, 0x0e, 0xb0, 0x49, 0x2a, 0xbe, 0xca, 0x25, 0xbf, 0xac, 0xdd, 0x6a, 0x24, 0xbb,
	0x80, 0xfb, 0x42, 0x16, 0x95, 0x42, 0xad, 0x33, 0x59, 0xce, 0x79, 0xbe, 0x90, 0x2a, 0x33, 0x69,
	0x41, 0xe6, 0x6d, 0x1f, 0xee, 0x46, 0xf5, 0xc9, 0x1e, 0xb7, 0x41, 0x47, 0x4d, 0x4c, 0x3c, 0x14,
	0xbf, 0xa1, 0xec, 0x1c, 0x86, 0x58, 0xd2, 0x6f, 0x3f, 0x67, 0xf4, 0x29, 0xe3, 0xc3, 0x26, 0xe3,
	0xc9, 0x3a, 0xa6, 0x4d, 0xb8, 0x83, 0xb7, 0xa1, 0xf5, 0x47, 0x67, 0x8b, 0x92, 0x9b, 0xa5, 0xc2,
	0xb0, 0x47, 0xed, 0xb7, 0x80, 0x9d, 0xc2, 0xce, 0x5a, 0xdc, 0x28, 0xb6, 0x45, 0xc5, 0x46, 0x4d,
	0xb1, 0x77, 0x4d, 0x48, 0x5b, 0x8b, 0xe9, 0x5b, 0x8c, 0x3d, 0x85, 0x40, 0xe1, 0x47, 0x54, 0x68,
	0x2f, 0x4a, 0x40, 0xae, 0xde, 0x71, 0xae, 0xd6, 0x30, 0x6e, 0xd7, 0xd9, 0x14, 0x36, 0x0b, 0x34,
	0x3c, 0x04, 0x8a, 0x1b, 0xde, 0x70, 0xff, 0x0d, 0x1a, 0xee, 0x2e, 0x10, 0x45, 0x8c, 0xbe, 0x78,
	0xe0, 0xbb, 0x13, 0xb1, 0xd7, 0x90, 0xe7, 0x19, 0xd7, 0x74, 0xd0, 0x41, 0xec, 0x04, 0xdb, 0x03,
	0xd0, 0x28, 0x14, 0x9a, 0xf9, 0x15, 0xae, 0xe8, 0x9c, 0xed, 0x1e, 0x89, 0x9c, 0xe2, 0xea, 0x8f,
	0x8e, 0x76, 0xfe, 0xcd, 0xd1, 0xd1, 0x73, 0x08, 0xd6, 0x2d, 0xb2, 0xbb, 0xd0, 0xb1, 0x45, 0x5d,
	0x3f, 0xf6, 0xd3, 0xf6, 0x78, 0xcd, 0xf3, 0x65, 0x33, 0x90, 0x4e, 0xbc, 0xdc, 0x78, 0xe1, 0x4d,
	0xbe, 0x7a, 0x10, 0xac, 0xbd, 0xf8, 0xff, 0xe9, 0xde, 0x03, 0x48, 0xec, 0x5c, 0xb9, 0x41, 0xea,
	0xb8, 0x6d, 0x13, 0xa1, 0x39, 0xfa, 0x65, 0xd0, 0x36, 0x6f, 0x0d, 0xda, 0x10, 0xba, 0x59, 0x79,
	0x89, 0x9f, 0xe9, 0xb2, 0xfa, 0xb1, 0x13, 0xb3, 0x57, 0xb0, 0x23, 0x64, 0x11, 0xf1, 0x1c, 0x4d,
	0x8a, 0x19, 0xff, 0xc4, 0x15, 0x46, 0x89, 0x98, 0xf5, 0x66, 0xc7, 0x6f, 0xed, 0xf3, 0xf4, 0x61,
	0x7f, 0x91, 0x99, 0x74, 0x99, 0x44, 0x42, 0x16, 0x07, 0x47, 0x75, 0xd0, 0x7b, 0xae, 0xf0, 0xec,
	0xec, 0xf8, 0x20, 0x11, 0x0b, 0x99, 0xf8, 0xf4, 0x8c, 0x3d, 0xfb, 0x11, 0x00, 0x00, 0xff, 0xff,
	0x61, 0xbf, 0x69, 0xb1, 0xe4, 0x04, 0x00, 0x00,
}
