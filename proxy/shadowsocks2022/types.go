package shadowsocks2022

import (
	"encoding/hex"
	"io"

	"github.com/v2fly/struc"

	commonErrors "github.com/v2fly/v2ray-core/v5/common/errors"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	// shared import removed as it's not needed by these types
)

type RequestSalt interface {
	struc.Custom
	isRequestSalt()
	Bytes() []byte
	FillAllFrom(reader io.Reader) error
	SetBytes(content []byte) error // Added SetBytes method
}

// TCP constants based on sing-shadowsocks
const (
	TCPHeaderTypeClientToServerStream byte = 0x00
	TCPHeaderTypeServerToClientStream byte = 0x01
	TCPMinPaddingLength               int  = 0 // Min padding length for client request
	TCPMaxPaddingLength               int  = 900 // Max padding length for client request - Keep this constant
)

// Re-adding TCP header structs aligned with sing-shadowsocks
// TCPRequestFixedHeader represents the first AEAD encrypted chunk after Salt [and EIH] from client.
type TCPRequestFixedHeader struct {
	Type                byte   // Should be TCPHeaderTypeClientToServerStream
	Timestamp           uint64 // Unix timestamp
	VariablePayloadLength uint16 // Length of the next AEAD chunk (DestAddr + Padding + InitialData)
}

// TCPResponseFixedHeader represents the AEAD encrypted chunk after Salt from server.
type TCPResponseFixedHeader struct {
	Type                 byte   // Should be TCPHeaderTypeServerToClientStream
	Timestamp            uint64 // Unix timestamp
	RequestSalt          []byte // Echoed Salt from client's request (length depends on method's KeySize)
	InitialPayloadLength uint16 // Length of initial payload data (usually 0 in sing-shadowsocks)
}


// AddrParser remains useful
var AddrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x04, net.AddressFamilyIPv6),
	protocol.AddressFamilyByte(0x03, net.AddressFamilyDomain),
)

const (
	UDPHeaderTypeClientToServerStream = byte(0x00)
	UDPHeaderTypeServerToClientStream = byte(0x01)
	// UDP constants
	UDPPacketHeaderSize        = 16 // For AES-GCM, the independent encrypted header
	UDPAEADNonceSize           = 12 // Standard AEAD nonce size for AES-GCM and ChaCha20's internal AEAD
	UDPMinPacketSize           = UDPPacketHeaderSize + 16 // Minimum for AES-GCM with its header
	UDPChaCha20PacketNonceSize = 24 // For ChaCha20 UDP, the large random nonce at the beginning of the packet
	UDPChaCha20MinPacketSize   = UDPChaCha20PacketNonceSize + 16 // Minimum for ChaCha20 (Nonce + minimal AEAD data)
)

func NewRequestSaltWithLength(length int) RequestSalt {
	return &requestSaltWithLength{length: length}
}

type requestSaltWithLength struct {
	length  int
	content []byte
}

func (r *requestSaltWithLength) isRequestSalt() {}

func (r *requestSaltWithLength) Pack(p []byte, opt *struc.Options) (int, error) {
	n := copy(p, r.content)
	if n != r.length {
		return 0, commonErrors.New("failed to pack request salt with length") 
	}
	return n, nil
}

func (r *requestSaltWithLength) Unpack(reader io.Reader, length int, opt *struc.Options) error {
	r.content = make([]byte, r.length)
	n, err := io.ReadFull(reader, r.content)
	if err != nil {
		return commonErrors.New("failed to unpack request salt with length").Base(err) 
	}
	if n != r.length {
		return commonErrors.New("failed to unpack request salt with length") 
	}
	return nil
}

// SetBytes sets the content of the salt directly.
func (r *requestSaltWithLength) SetBytes(content []byte) error {
	if len(content) != r.length {
		// If length is fixed, enforce it. If not initialized, set it.
		if r.length > 0 {
			return commonErrors.New("provided content length mismatch for RequestSalt")
		}
		r.length = len(content)
	}
	// Create a new slice and copy content to avoid aliasing issues
	r.content = make([]byte, len(content))
	copy(r.content, content)
	return nil
}

func (r *requestSaltWithLength) Size(opt *struc.Options) int {
	return r.length
}

func (r *requestSaltWithLength) String() string {
	return hex.Dump(r.content)
}

func (r *requestSaltWithLength) Bytes() []byte {
	return r.content
}

func (r *requestSaltWithLength) FillAllFrom(reader io.Reader) error {
	r.content = make([]byte, r.length)
	_, err := io.ReadFull(reader, r.content)
	if err != nil {
		return commonErrors.New("failed to fill salt from reader").Base(err) 
	}
	return nil
}
