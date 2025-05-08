package encoding

import (
	"bytes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	commonErrors "github.com/v2fly/v2ray-core/v5/common/errors"
	"github.com/v2fly/v2ray-core/v5/common/crypto"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022" 
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/shared" 

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	mRand "math/rand"
)


type TCPRequest struct {
	Method        shared.Method 

	c2sSalt  shadowsocks2022.RequestSalt 
	c2sNonce crypto.BytesGenerator
	c2sAEAD  cipher.AEAD

	s2cSalt  shadowsocks2022.RequestSalt 
	s2cNonce crypto.BytesGenerator
	s2cAEAD  cipher.AEAD

	s2cSaltAssert         shadowsocks2022.RequestSalt 
	s2cInitialPayloadSize int
}

// EncodeTCPRequestHeader encodes the header using the sing-shadowsocks two-stage format.
// Format: Salt | AEAD(Len1) | AEAD(Header1) | AEAD(Len2) | AEAD(Header2+Payload)
func (t *TCPRequest) EncodeTCPRequestHeader(effectivePsk []byte,
	decodedIpsk [][]byte, address net.Address, destPort int, initialPayload []byte, out *buf.Buffer, 
) error {
	requestSalt := shadowsocks2022.NewRequestSaltWithLength(t.Method.GetSessionSubKeyAndSaltLength()) 
	if err := requestSalt.FillAllFrom(cryptoRand.Reader); err != nil {
		return commonErrors.New("failed to fill salt").Base(err)
	}
	t.c2sSalt = requestSalt

	methodName := t.Method.Name()
	methodInfo, ok := shadowsocks2022.MethodMap[methodName]
	if !ok {
		return commonErrors.New("client: method info not found for ", methodName)
	}
	sessionKey, err := shadowsocks2022.SessionKey(effectivePsk, requestSalt.Bytes(), methodInfo.KeySize)
	if err != nil {
		return commonErrors.New("client: failed to derive session key").Base(err)
	}
	
	aead, err := t.Method.GetStreamAEAD(sessionKey) 
	if err != nil {
		return commonErrors.New("failed to get stream AEAD").Base(err)
	}
	t.c2sAEAD = aead
	t.c2sNonce = crypto.GenerateInitialAEADNonce()

	// Step 1: Write the client Salt (unencrypted)
	if _, err := out.Write(requestSalt.Bytes()); err != nil {
		return commonErrors.New("failed to write client salt").Base(err)
	}

	// Step 2: Prepare and write the first AEAD encrypted chunk (Fixed Header)
	// Content: Type, Timestamp, VariablePayloadLength
	paddingLength := shadowsocks2022.TCPMinPaddingLength
	if initialPayload == nil {
		initialPayload = []byte{}
		// Use math/rand for padding length, similar to sing-shadowsocks
		paddingLength += 1 + mRand.Intn(shadowsocks2022.TCPMaxPaddingLength) 
	}

	// Calculate VariablePayloadLength = DestAddrLen + PaddingLenField(2) + Padding + InitialDataLen
	variablePartBufferTemp := buf.New() // Temp buffer to calculate length
	defer variablePartBufferTemp.Release()
	if err := shadowsocks2022.AddrParser.WriteAddressPort(variablePartBufferTemp, address, net.Port(destPort)); err != nil {
		return commonErrors.New("failed to write address/port to temp buffer").Base(err)
	}
	variablePartAddrLen := variablePartBufferTemp.Len()
	variablePayloadLength := uint16(variablePartAddrLen) + 2 + uint16(paddingLength) + uint16(len(initialPayload))

	fixedHeaderContentPayload := &shadowsocks2022.TCPRequestFixedHeader{
		Type:                shadowsocks2022.TCPHeaderTypeClientToServerStream,
		Timestamp:           uint64(time.Now().Unix()),
		VariablePayloadLength: variablePayloadLength,
	}

	fixedHeaderContentBuffer := buf.New() 
	defer fixedHeaderContentBuffer.Release()
	binary.Write(fixedHeaderContentBuffer, binary.BigEndian, fixedHeaderContentPayload.Type)
	binary.Write(fixedHeaderContentBuffer, binary.BigEndian, fixedHeaderContentPayload.Timestamp)
	binary.Write(fixedHeaderContentBuffer, binary.BigEndian, fixedHeaderContentPayload.VariablePayloadLength)

	// Encrypt and write the fixed header (length first, then content)
	{
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(fixedHeaderContentBuffer.Len())) // Length of fixed header content
		
		encryptedLenBlock := out.Extend(2 + int32(aead.Overhead()))
		aead.Seal(encryptedLenBlock[:0], t.c2sNonce() /* Nonce 0 */, lenBytes, nil)
		
		encryptedDataBlock := out.Extend(fixedHeaderContentBuffer.Len() + int32(aead.Overhead()))
		aead.Seal(encryptedDataBlock[:0], t.c2sNonce() /* Nonce 1 */, fixedHeaderContentBuffer.Bytes(), nil)
	}

	// Step 3: Prepare and write the second AEAD encrypted chunk (Variable Header + Initial Data)
	// Content: DestAddr, PaddingLength, Padding, InitialData
	variablePayloadBuffer := buf.New()
	defer variablePayloadBuffer.Release()
	if err := shadowsocks2022.AddrParser.WriteAddressPort(variablePayloadBuffer, address, net.Port(destPort)); err != nil {
		return commonErrors.New("failed to write address/port for variable payload").Base(err)
	}
	binary.Write(variablePayloadBuffer, binary.BigEndian, uint16(paddingLength)) // PaddingLength
	variablePayloadBuffer.Write(make([]byte, paddingLength)) // Padding
	variablePayloadBuffer.Write(initialPayload) // InitialData
	
	// Encrypt and write the variable payload (length first, then content)
	{
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(variablePayloadBuffer.Len())) // Length of variable payload content
		
		encryptedLenBlock := out.Extend(2 + int32(aead.Overhead()))
		aead.Seal(encryptedLenBlock[:0], t.c2sNonce() /* Nonce 2 */, lenBytes, nil)

		encryptedDataBlock := out.Extend(variablePayloadBuffer.Len() + int32(aead.Overhead()))
		aead.Seal(encryptedDataBlock[:0], t.c2sNonce() /* Nonce 3 */, variablePayloadBuffer.Bytes(), nil)
	}
	return nil
}

// DecodeTCPResponseHeader decodes the header using the sing-shadowsocks two-stage format.
// Format: Salt | AEAD(Len) | AEAD(Header)
func (t *TCPRequest) DecodeTCPResponseHeader(effectivePsk []byte, in io.Reader) error {
	// Step 1: Read the server's Salt (unencrypted)
	serverSaltLen := t.Method.GetSessionSubKeyAndSaltLength()
	serverSaltBytes := make([]byte, serverSaltLen)
	if _, err := io.ReadFull(in, serverSaltBytes); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return commonErrors.New("connection closed by server or no response header received").Base(err)
		}
		return commonErrors.New("failed to read server salt").Base(err)
	}
	
	t.s2cSalt = shadowsocks2022.NewRequestSaltWithLength(serverSaltLen)
	if err := t.s2cSalt.SetBytes(serverSaltBytes); err != nil { 
		return commonErrors.New("failed to set server salt bytes").Base(err)
	}

	methodName := t.Method.Name()
	methodInfo, ok := shadowsocks2022.MethodMap[methodName]
	if !ok {
		return commonErrors.New("client: method info not found for ", methodName)
	}

	// Step 2: Derive S2C session key using server's salt and PSK
	s2cSessionKey, err := shadowsocks2022.SessionKey(effectivePsk, serverSaltBytes, methodInfo.KeySize)
	if err != nil {
		return commonErrors.New("client: failed to derive S2C session key").Base(err)
	}

	s2cAEAD, err := t.Method.GetStreamAEAD(s2cSessionKey)
	if err != nil {
		return commonErrors.New("failed to create S2C stream AEAD").Base(err)
	}
	t.s2cAEAD = s2cAEAD
	t.s2cNonce = crypto.GenerateInitialAEADNonce() 

	// Step 3: Read and decrypt the server's response header chunk (fixed part)
	// This corresponds to the fixed response header sent by the server.
	// Server sends: AEAD(Nonce0, len(FixedRespHeaderContent)) then AEAD(Nonce1, FixedRespHeaderContent)

	encryptedRespHeaderPayloadLenBytes := make([]byte, 2+t.s2cAEAD.Overhead())
	if _, err := io.ReadFull(in, encryptedRespHeaderPayloadLenBytes); err != nil {
		return commonErrors.New("failed to read encrypted length of response header payload").Base(err)
	}
	
	decryptedRespHeaderPayloadLenBytes, err := t.s2cAEAD.Open(nil, t.s2cNonce() /* Nonce 0 */, encryptedRespHeaderPayloadLenBytes, nil)
	if err != nil {
		return commonErrors.New("failed to decrypt response header payload length").Base(err)
	}
	respHeaderPayloadLen := binary.BigEndian.Uint16(decryptedRespHeaderPayloadLenBytes)

	// Read encrypted response header payload
	encryptedRespHeaderPayload := make([]byte, int(respHeaderPayloadLen)+t.s2cAEAD.Overhead())
	if _, err := io.ReadFull(in, encryptedRespHeaderPayload); err != nil {
		return commonErrors.New("failed to read encrypted response header payload").Base(err)
	}

	decryptedRespHeaderPayload, err := t.s2cAEAD.Open(nil, t.s2cNonce() /* Nonce 1 */, encryptedRespHeaderPayload, nil)
	if err != nil {
		return commonErrors.New("failed to decrypt response header payload").Base(err)
	}

	// Parse the TCPResponseFixedHeader
	respHeaderReader := bytes.NewReader(decryptedRespHeaderPayload)
	var fixedResponseHeader shadowsocks2022.TCPResponseFixedHeader
	
    if err := binary.Read(respHeaderReader, binary.BigEndian, &fixedResponseHeader.Type); err != nil {
        return commonErrors.New("failed to read Type from response header").Base(err)
    }
    if err := binary.Read(respHeaderReader, binary.BigEndian, &fixedResponseHeader.Timestamp); err != nil {
        return commonErrors.New("failed to read Timestamp from response header").Base(err)
    }
    
    // Read RequestSalt (echoed client's original salt)
    echoedClientSaltLen := t.Method.GetSessionSubKeyAndSaltLength() 
    fixedResponseHeader.RequestSalt = make([]byte, echoedClientSaltLen)
    if _, err := io.ReadFull(respHeaderReader, fixedResponseHeader.RequestSalt); err != nil {
        return commonErrors.New("failed to read echoed RequestSalt from response header").Base(err)
    }
    if err := binary.Read(respHeaderReader, binary.BigEndian, &fixedResponseHeader.InitialPayloadLength); err != nil {
        return commonErrors.New("failed to read InitialPayloadLength from response header").Base(err)
    }

	if fixedResponseHeader.Type != shadowsocks2022.TCPHeaderTypeServerToClientStream {
		return commonErrors.New("unexpected TCP response header type")
	}
	timeDifference := int64(fixedResponseHeader.Timestamp) - time.Now().Unix()
	if timeDifference < -30 || timeDifference > 30 {
		return commonErrors.New("response timestamp is too far away, timeDifference = ", timeDifference)
	}

	// Store the echoed client salt for assertion
	t.s2cSaltAssert = shadowsocks2022.NewRequestSaltWithLength(len(fixedResponseHeader.RequestSalt))
	if err := t.s2cSaltAssert.SetBytes(fixedResponseHeader.RequestSalt); err != nil {
		return commonErrors.New("failed to set asserted client salt bytes").Base(err)
	}
	
	t.s2cInitialPayloadSize = int(fixedResponseHeader.InitialPayloadLength) 
	// In sing-shadowsocks, InitialPayloadLength in response header is 0.
	return nil
}

// CheckC2SConnectionConstraint checks if the echoed salt matches the original client salt.
func (t *TCPRequest) CheckC2SConnectionConstraint() error {
	if t.c2sSalt == nil || t.s2cSaltAssert == nil {
       return commonErrors.New("salts for assertion are not initialized")
    }
	if !bytes.Equal(t.c2sSalt.Bytes(), t.s2cSaltAssert.Bytes()) {
		return commonErrors.New("c2s salt not equal to s2c salt assert")
	}
	return nil
}

func (t *TCPRequest) CreateClientS2CReader(in io.Reader, initialPayload *buf.Buffer) (buf.Reader, error) {
	AEADAuthenticator := &crypto.AEADAuthenticator{
		AEAD:                    t.s2cAEAD,
		NonceGenerator:          t.s2cNonce,
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	// If s2cInitialPayloadSize is 0, initialPayload buffer will remain empty.
	if t.s2cInitialPayloadSize > 0 {
		// This part might be unnecessary if sing-shadowsocks always sends initial payload as a separate chunk.
		// Keeping it for now, but if issues persist, consider removing this initial read.
		initialPayloadEncrypted := buf.NewWithSize(65535)
		defer initialPayloadEncrypted.Release()
		initialPayloadEncryptedBytes := initialPayloadEncrypted.Extend(int32(t.s2cAEAD.Overhead()) + int32(t.s2cInitialPayloadSize))
		_, err := io.ReadFull(in, initialPayloadEncryptedBytes)
		if err != nil {
			return nil, commonErrors.New("failed to read initial payload").Base(err)
		}
		initialPayloadBytes := initialPayload.Extend(int32(t.s2cInitialPayloadSize))
		// Use the next nonce (Nonce 1) to decrypt initial payload, assuming header used Nonce 0.
		_, err = t.s2cAEAD.Open(initialPayloadBytes[:0], t.s2cNonce(), initialPayloadEncryptedBytes, nil) 
		if err != nil {
			return nil, commonErrors.New("failed to decrypt initial payload").Base(err)
		}
	} else {
		initialPayload.Resize(0,0) 
	}

	return crypto.NewAuthenticationReader(AEADAuthenticator, &AEADChunkSizeParser{
		Auth: AEADAuthenticator,
	}, in, protocol.TransferTypeStream, nil), nil
}

func (t *TCPRequest) CreateClientC2SWriter(writer io.Writer) buf.Writer {
	AEADAuthenticator := &crypto.AEADAuthenticator{
		AEAD:                    t.c2sAEAD,
		NonceGenerator:          t.c2sNonce,
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	sizeParser := &AEADChunkSizeParser{
		Auth: AEADAuthenticator,
	}
	return crypto.NewAuthenticationWriter(AEADAuthenticator, sizeParser, writer, protocol.TransferTypeStream, nil)
}

type AEADChunkSizeParser struct {
	Auth *crypto.AEADAuthenticator
}

func (p *AEADChunkSizeParser) HasConstantOffset() uint16 {
	return uint16(p.Auth.Overhead())
}

func (p *AEADChunkSizeParser) SizeBytes() int32 {
	return 2 + int32(p.Auth.Overhead())
}

func (p *AEADChunkSizeParser) Encode(size uint16, b []byte) []byte {
	binary.BigEndian.PutUint16(b, size-uint16(p.Auth.Overhead()))
	b, err := p.Auth.Seal(b[:0], b[:2])
	common.Must(err)
	return b
}

func (p *AEADChunkSizeParser) Decode(b []byte) (uint16, error) {
	b, err := p.Auth.Open(b[:0], b)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}
