package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/v2fly/struc"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	commonErrors "github.com/v2fly/v2ray-core/v5/common/errors"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022" // For MethodInfo, AddrParser, constants
	ss2022types "github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022" // Alias for local constants
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/shared"
)

// ChaCha20UDPClientPacketProcessor implements shared.UDPClientPacketProcessor for ChaCha20-Poly1305.
type ChaCha20UDPClientPacketProcessor struct {
	psk        []byte // Main Pre-Shared Key
	methodInfo *shadowsocks2022.MethodInfo
}

// NewChaCha20UDPClientPacketProcessor creates a new processor for ChaCha20 UDP.
func NewChaCha20UDPClientPacketProcessor(psk []byte, methodInfo *shadowsocks2022.MethodInfo) (*ChaCha20UDPClientPacketProcessor, error) {
	if len(psk) != methodInfo.KeySize {
		return nil, commonErrors.New("ChaCha20UDPClientPacketProcessor: incorrect PSK length")
	}
	return &ChaCha20UDPClientPacketProcessor{
		psk:        psk,
		methodInfo: methodInfo,
	}, nil
}

// EncodeUDPRequest encodes a UDP request for ChaCha20.
// Format: [24-byte PacketNonce][AEAD(PSK, PacketNonce, ClientSessionID|PacketID|Metadata|Payload, nil)]
func (p *ChaCha20UDPClientPacketProcessor) EncodeUDPRequest(request *shared.UDPRequest, out *buf.Buffer, cache shared.UDPClientPacketProcessorCachedStateContainer) error {
	packetNonce := make([]byte, ss2022types.UDPChaCha20PacketNonceSize)
	if _, err := io.ReadFull(rand.Reader, packetNonce); err != nil {
		return commonErrors.New("failed to generate packet nonce for ChaCha20 UDP request").Base(err)
	}
	out.Write(packetNonce)

	metadataAndPayloadBuf := buf.New()
	defer metadataAndPayloadBuf.Release()

	// Write SessionID and PacketID first as per sing-shadowsocks ChaCha20 UDP format
	metadataAndPayloadBuf.Write(request.SessionID[:])
	metadataAndPayloadBuf.Write(binary.BigEndian.AppendUint64(nil, request.PacketID))

	// Then write Type, Timestamp, Padding, Address, Port, Payload
	// Padding is simplified for now, similar to sing-shadowsocks client.
	paddingLen := 0
	// Example: if request.Address.Family().IsDomain() && request.Port == 53 { paddingLen = ... }

	headerStruct := struct {
		Type          byte
		Timestamp     uint64
		PaddingLength uint16 `struc:"sizeof=Padding"`
		Padding       []byte
	}{
		Type:          ss2022types.UDPHeaderTypeClientToServerStream,
		Timestamp:     request.TimeStamp,
		PaddingLength: uint16(paddingLen),
		Padding:       make([]byte, paddingLen),
	}

	if err := struc.Pack(metadataAndPayloadBuf, &headerStruct); err != nil {
		return commonErrors.New("failed to pack ChaCha20 UDP request header").Base(err)
	}

	if err := ss2022types.AddrParser.WriteAddressPort(metadataAndPayloadBuf, request.Address, net.Port(request.Port)); err != nil {
		return commonErrors.New("failed to write address and port for ChaCha20 UDP request").Base(err)
	}

	if _, err := metadataAndPayloadBuf.Write(request.Payload.Bytes()); err != nil {
		return commonErrors.New("failed to write payload for ChaCha20 UDP request").Base(err)
	}

	aead, err := chacha20poly1305.NewX(p.psk) // AEAD uses main PSK and 24-byte nonce
	if err != nil {
		return commonErrors.New("failed to create ChaCha20 AEAD for UDP request").Base(err)
	}

	encryptedPayloadBytes := out.Extend(metadataAndPayloadBuf.Len() + int32(aead.Overhead()))
	aead.Seal(encryptedPayloadBytes[:0], packetNonce, metadataAndPayloadBuf.Bytes(), nil) // AAD is nil

	return nil
}

// DecodeUDPResp decodes a UDP response for ChaCha20.
// Format: [24-byte PacketNonce][AEAD(PSK, PacketNonce, ServerSessionID|ServerPacketID|ClientSessionID|Metadata|Payload, nil)]
func (p *ChaCha20UDPClientPacketProcessor) DecodeUDPResp(input []byte, resp *shared.UDPResponse, cache shared.UDPClientPacketProcessorCachedStateContainer) error {
	if len(input) < ss2022types.UDPChaCha20MinPacketSize {
		return commonErrors.New("ChaCha20 UDP response packet too short")
	}

	packetNonce := input[:ss2022types.UDPChaCha20PacketNonceSize]
	encryptedData := input[ss2022types.UDPChaCha20PacketNonceSize:]

	aead, err := chacha20poly1305.NewX(p.psk) // AEAD uses main PSK and 24-byte nonce
	if err != nil {
		return commonErrors.New("failed to create ChaCha20 AEAD for UDP response").Base(err)
	}

	decryptedPayloadBytes := make([]byte, len(encryptedData)-aead.Overhead())
	_, err = aead.Open(decryptedPayloadBytes[:0], packetNonce, encryptedData, nil) // AAD is nil
	if err != nil {
		return commonErrors.New("failed to decrypt ChaCha20 UDP response").Base(err)
	}

	payloadReader := bytes.NewReader(decryptedPayloadBytes)

	// Read ServerSessionID and ServerPacketID
	if _, err := io.ReadFull(payloadReader, resp.SessionID[:]); err != nil { // Server's SessionID
		return commonErrors.New("failed to read server SessionID from ChaCha20 UDP response").Base(err)
	}
	if err := binary.Read(payloadReader, binary.BigEndian, &resp.PacketID); err != nil { // Server's PacketID
		return commonErrors.New("failed to read server PacketID from ChaCha20 UDP response").Base(err)
	}

	// Read Type, Timestamp, ClientOriginalSessionID, Padding, Original Destination, Actual Payload
	respHeaderStruct := struct {
		Type                byte
		Timestamp           uint64
		ClientOrigSessionID [8]byte
		PaddingLength       uint16 `struc:"sizeof=Padding"`
		Padding             []byte
	}{}
	if err := struc.Unpack(payloadReader, &respHeaderStruct); err != nil {
		return commonErrors.New("failed to unpack ChaCha20 UDP response header").Base(err)
	}

	// resp.Type = respHeaderStruct.Type // shared.UDPResponse does not have Type field
	resp.TimeStamp = respHeaderStruct.Timestamp
	resp.ClientSessionID = respHeaderStruct.ClientOrigSessionID // Echoed ClientSessionID

	// Skip padding
	if _, err := payloadReader.Seek(int64(respHeaderStruct.PaddingLength), io.SeekCurrent); err != nil {
		return commonErrors.New("failed to skip padding in ChaCha20 UDP response").Base(err)
	}

	var port net.Port
	address, port, err := ss2022types.AddrParser.ReadAddressPort(nil, payloadReader)
	if err != nil {
		return commonErrors.New("failed to read address and port from ChaCha20 UDP response").Base(err)
	}
	resp.Address = address
	resp.Port = int(port)

	resp.Payload = buf.New()
	// Read remaining as actual payload
	if _, err := resp.Payload.ReadFrom(payloadReader); err != nil {
		resp.Payload.Release()
		return commonErrors.New("failed to read payload from ChaCha20 UDP response").Base(err)
	}

	return nil
}
