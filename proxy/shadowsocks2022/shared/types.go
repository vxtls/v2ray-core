package shared

import (
	"crypto/cipher"

	"github.com/v2fly/struc"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/net"
)

type KeyDerivation interface {
	GetSessionSubKey(effectivePsk, Salt []byte, OutKey []byte) error
	GetIdentitySubKey(effectivePsk, Salt []byte, OutKey []byte) error
}

type Method interface {
	Name() string
	GetSessionSubKeyAndSaltLength() int
	GetStreamAEAD(SessionSubKey []byte) (cipher.AEAD, error)
	EncryptEIHPart(identityKey []byte, pskHashToEncrypt []byte, outputBuffer []byte) error
	GetUDPClientProcessor(ipsk [][]byte, psk []byte) (UDPClientPacketProcessor, error)
}

type ExtensibleIdentityHeaders interface {
	struc.Custom
}

type DestinationAddress interface {
	net.Address
}

type UDPRequest struct {
	SessionID [8]byte
	PacketID  uint64
	TimeStamp uint64
	Address   DestinationAddress
	Port      int
	Payload   *buf.Buffer
}

type UDPResponse struct {
	UDPRequest
	ClientSessionID [8]byte
}

type UDPClientPacketProcessorCachedStateContainer interface {
	GetCachedState(sessionID string) UDPClientPacketProcessorCachedState
	PutCachedState(sessionID string, cache UDPClientPacketProcessorCachedState)
	GetCachedServerState(serverSessionID string) UDPClientPacketProcessorCachedState
	PutCachedServerState(serverSessionID string, cache UDPClientPacketProcessorCachedState)
}

type UDPClientPacketProcessorCachedState interface{}

type UDPClientPacketProcessor interface {
	EncodeUDPRequest(request *UDPRequest, out *buf.Buffer, cache UDPClientPacketProcessorCachedStateContainer) error
	DecodeUDPResp(input []byte, resp *UDPResponse, cache UDPClientPacketProcessorCachedStateContainer) error
}
