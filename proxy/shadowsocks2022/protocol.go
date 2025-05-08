package shadowsocks2022

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"io"
	"time"

	"crypto/aes"
	"crypto/rand"
	"github.com/v2fly/struc"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	v2rayErrors "github.com/v2fly/v2ray-core/v5/common/errors"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"net"
)

var SupportedMethods = []string{
	"2022-blake3-aes-128-gcm",
	"2022-blake3-aes-256-gcm",
	"2022-blake3-chacha20-poly1305",
}

type MethodInfo struct {
	KeySize   int
	NonceSize int
	TagSize   int
	New       func(key []byte) (cipher.AEAD, error)
	Hash      func() hash.Hash
}

var MethodMap = map[string]MethodInfo{
	"2022-blake3-aes-128-gcm": {
		KeySize:   16,
		NonceSize: 12,
		TagSize:   16,
		New: func(key []byte) (cipher.AEAD, error) {
			c, err := aes.NewCipher(key)
			if err != nil { return nil, err }
			return cipher.NewGCM(c)
		},
		Hash: sha256.New,
	},
	"2022-blake3-aes-256-gcm": {
		KeySize:   32,
		NonceSize: 12,
		TagSize:   16,
		New: func(key []byte) (cipher.AEAD, error) {
			c, err := aes.NewCipher(key)
			if err != nil { return nil, err }
			return cipher.NewGCM(c)
		},
		Hash: sha512.New384,
	},
	"2022-blake3-chacha20-poly1305": {
		KeySize:   32,
		NonceSize: 12, // Standard ChaCha20 nonce size
		TagSize:   16,
		New:       chacha20poly1305.New, // Use standard ChaCha20Poly1305 which expects 12-byte nonce internally
		Hash:      sha256.New,
	},
}

type InboundProtocolHandler interface {
	HandleTCPConnection(ctx context.Context, conn internet.Connection, source v2rayNet.Destination, destination v2rayNet.Destination, dispatcher routing.Dispatcher) error 
	HandleUDPPacket(ctx context.Context, packet *buf.Buffer, source v2rayNet.Destination, destination v2rayNet.Destination, dispatcher routing.Dispatcher) error           
	HandleError(ctx context.Context, err error)
}

type Shadowsocks2022Service interface {
	ProcessConnection(ctx context.Context, conn internet.Connection, network v2rayNet.Network, source v2rayNet.Destination, dispatcher routing.Dispatcher) error 
	NewError(ctx context.Context, err error)
	EncryptUDPResponse(ctx context.Context, payloadToEncrypt *buf.Buffer, clientOriginalSessionID [8]byte, originalDest v2rayNet.Destination) (*buf.Buffer, error) 
}

type Shadowsocks2022ServiceImpl struct {
	method          string
	key             []byte // This is the original PSK
	methodInfo      MethodInfo
	protocolHandler InboundProtocolHandler
}

func SessionKey(psk []byte, saltOrSessionID []byte, keyLength int) ([]byte, error) {
	if len(psk) == 0 || len(saltOrSessionID) == 0 {
		return nil, v2rayErrors.New("PSK or salt/sessionID cannot be empty for KDF") 
	}
	sessionKeyInput := make([]byte, len(psk)+len(saltOrSessionID))
	copy(sessionKeyInput, psk)
	copy(sessionKeyInput[len(psk):], saltOrSessionID)
	outKey := make([]byte, keyLength)
	blake3.DeriveKey(outKey, "shadowsocks 2022 session subkey", sessionKeyInput)
	return outKey, nil
}

func NewShadowsocks2022ServiceWithPassword(method string, password string, timeout int, handler InboundProtocolHandler, options interface{}) (Shadowsocks2022Service, error) {
	methodInfo, ok := MethodMap[method] 
	if !ok {
		return nil, v2rayErrors.New("unsupported method: " + method)
	}

	pskBytesUncoded, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return nil, v2rayErrors.New("failed to decode PSK from base64").Base(err)
	}
	pskBytes := pskBytesUncoded

	if len(pskBytes) != methodInfo.KeySize {
		if len(pskBytes) < methodInfo.KeySize {
			return nil, v2rayErrors.New("decoded PSK is shorter than required key size: ", len(pskBytes), " < ", methodInfo.KeySize, ". This is considered an error (ErrBadKey in sing-shadowsocks).")
		}
		v2rayErrors.New("PSK length after base64 decode mismatch: expected ", methodInfo.KeySize, " got ", len(pskBytes), ". Deriving key with SHA256.").AtWarning().WriteToLog()
		hashedPsk := sha256.Sum256(pskBytes)
		pskBytes = hashedPsk[:methodInfo.KeySize]
	}

	return &Shadowsocks2022ServiceImpl{
		method:          method,
		key:             pskBytes, // Store the final (possibly derived) PSK
		methodInfo:      methodInfo,
		protocolHandler: handler,
	}, nil
}

func (s *Shadowsocks2022ServiceImpl) ProcessConnection(ctx context.Context, conn internet.Connection, network v2rayNet.Network, source v2rayNet.Destination, dispatcher routing.Dispatcher) error { 
	if network == v2rayNet.Network_TCP { 
		return s.handleTCPConnection(ctx, conn, source, dispatcher)
	} else if network == v2rayNet.Network_UDP { 
		pc, ok := conn.(internet.PacketConn)
		if !ok {
			return v2rayErrors.New("connection is not a PacketConn for UDP")
		}
		buffer := buf.New()
		defer buffer.Release()

		n, sourceAddr, err := pc.ReadFrom(buffer.Extend(buf.Size))
		if err != nil {
			// Don't return error directly, let dispatcher handle potential downstream errors. Log it.
			s.NewError(ctx, v2rayErrors.New("failed to read UDP packet from connection").Base(err))
			return nil // Return nil to allow other potential packets? Or return err? sing-box returns err. Let's return err.
			// return err 
		}
		buffer.Resize(0, int32(n))
		sourceDest := v2rayNet.DestinationFromAddr(sourceAddr) 
		return s.handleUDPPacket(ctx, buffer, sourceDest, dispatcher)

	} else {
		return v2rayErrors.New("unsupported network type in service: " + network.String())
	}
}

func (s *Shadowsocks2022ServiceImpl) NewError(ctx context.Context, err error) {
	s.protocolHandler.HandleError(ctx, err)
}

func (s *Shadowsocks2022ServiceImpl) handleTCPConnection(ctx context.Context, conn internet.Connection, source v2rayNet.Destination, dispatcher routing.Dispatcher) error { 
	clientSalt := make([]byte, s.methodInfo.KeySize) 
	if _, err := io.ReadFull(conn, clientSalt); err != nil {
		s.NewError(ctx, v2rayErrors.New("failed to read client salt").Base(err))
		return err
	}

	c2sSessionKey, err := SessionKey(s.key, clientSalt, s.methodInfo.KeySize)
	if err != nil {
		s.NewError(ctx, v2rayErrors.New("failed to derive C2S session key").Base(err))
		return err
	}

	c2sAEAD, err := s.methodInfo.New(c2sSessionKey) 
	if err != nil {
		s.NewError(ctx, v2rayErrors.New("failed to create C2S AEAD cipher").Base(err))
		return err
	}

	// Initialize wrappedConn with C2S context and original PSK for S2C keying later
	wrappedConn := &Ss2022WrappedConnection{
		Connection:          conn,
		originalPSK:         s.key, 
		methodInfo:          s.methodInfo,
		clientSalt:          append([]byte(nil), clientSalt...), 
		c2sAEAD:             c2sAEAD,
		decryptNonceCounter: 0,
		// s2cAEAD and s2cEncryptNonceCounter will be initialized on first write
		responseHeaderSent:     false,
	}

	destination, remainingBuffer, err := wrappedConn.readAndDecryptHeader(ctx) 
	if err != nil {
		s.NewError(ctx, v2rayErrors.New("failed to read and decrypt header").Base(err))
		return err
	}

	wrappedConn.decryptBuffer = remainingBuffer

	return s.protocolHandler.HandleTCPConnection(ctx, wrappedConn, source, destination, dispatcher)
}

// handleUDPPacket remains the same as the previously corrected version (handling ChaCha20 differently)
func (s *Shadowsocks2022ServiceImpl) handleUDPPacket(ctx context.Context, packet *buf.Buffer, source v2rayNet.Destination, dispatcher routing.Dispatcher) error {
	var clientSessionID [8]byte
	var clientPacketID uint64
	var decryptedPayloadBytes []byte 

	if s.method == "2022-blake3-chacha20-poly1305" {
		if packet.Len() < UDPChaCha20MinPacketSize {
			s.NewError(ctx, v2rayErrors.New("UDP ChaCha20 packet too short"))
			packet.Release()
			return nil
		}
		packetNonce := packet.Bytes()[:UDPChaCha20PacketNonceSize]
		encryptedPayloadWithMetadata := packet.Bytes()[UDPChaCha20PacketNonceSize:]
		aead, err := s.methodInfo.New(s.key) // Use main PSK
		if err != nil {
			s.NewError(ctx, v2rayErrors.New("failed to create ChaCha20 AEAD cipher for UDP payload").Base(err))
			packet.Release(); return nil
		}
		decryptedPayloadBytes = make([]byte, len(encryptedPayloadWithMetadata)-aead.Overhead())
		// Use XChaCha20 24-byte nonce directly
		_, err = aead.Open(decryptedPayloadBytes[:0], packetNonce, encryptedPayloadWithMetadata, nil) 
		if err != nil {
			s.NewError(ctx, v2rayErrors.New("failed to decrypt ChaCha20 UDP payload").Base(err))
			packet.Release(); return nil
		}
		if len(decryptedPayloadBytes) < 16 { 
			s.NewError(ctx, v2rayErrors.New("ChaCha20 UDP decrypted payload too short for Session/Packet ID"))
			packet.Release(); return nil
		}
		copy(clientSessionID[:], decryptedPayloadBytes[0:8])
		clientPacketID = binary.BigEndian.Uint64(decryptedPayloadBytes[8:16])
		decryptedPayloadBytes = decryptedPayloadBytes[16:]
	} else { // AES-GCM methods
		if packet.Len() < UDPMinPacketSize {
			s.NewError(ctx, v2rayErrors.New("UDP AES-GCM packet too short"))
			packet.Release(); return nil
		}
		encryptedIndependentHeader := packet.Bytes()[:UDPPacketHeaderSize]
		cleartextIndependentHeaderBytes := make([]byte, UDPPacketHeaderSize)
		headerCipher, err := aes.NewCipher(s.key) 
		if err != nil {
			s.NewError(ctx, v2rayErrors.New("failed to create AES cipher for UDP independent header").Base(err))
			packet.Release(); return nil
		}
		headerCipher.Decrypt(cleartextIndependentHeaderBytes, encryptedIndependentHeader)
		copy(clientSessionID[:], cleartextIndependentHeaderBytes[0:8])
		clientPacketID = binary.BigEndian.Uint64(cleartextIndependentHeaderBytes[8:16])
		aeadEncryptedPayload := packet.Bytes()[UDPPacketHeaderSize:]
		aeadKey, err := SessionKey(s.key, clientSessionID[:], s.methodInfo.KeySize)
		if err != nil {
			s.NewError(ctx, v2rayErrors.New("failed to derive AEAD key for UDP payload").Base(err))
			packet.Release(); return nil
		}
		aead, err := s.methodInfo.New(aeadKey)
		if err != nil {
			s.NewError(ctx, v2rayErrors.New("failed to create AEAD cipher for UDP payload").Base(err))
			packet.Release(); return nil
		}
		nonce := make([]byte, UDPAEADNonceSize)
		copy(nonce[0:4], cleartextIndependentHeaderBytes[4:8])  
		copy(nonce[4:12], cleartextIndependentHeaderBytes[8:16]) 
		decryptedPayloadBytes = make([]byte, len(aeadEncryptedPayload)-aead.Overhead())
		_, err = aead.Open(decryptedPayloadBytes[:0], nonce, aeadEncryptedPayload, nil)
		if err != nil {
			s.NewError(ctx, v2rayErrors.New("failed to decrypt AES-GCM UDP payload").Base(err))
			packet.Release(); return nil
		}
	}

	payloadReader := bytes.NewReader(decryptedPayloadBytes)
	mainHeader := struct { 
		Type          byte
		Timestamp     uint64
		PaddingLength uint16 `struc:"sizeof=Padding"`
		Padding       []byte
	}{}
	if err := struc.Unpack(payloadReader, &mainHeader); err != nil {
		s.NewError(ctx, v2rayErrors.New("failed to unpack UDP main header from client").Base(err))
		packet.Release(); return nil
	}
	if _, err := payloadReader.Seek(int64(mainHeader.PaddingLength), io.SeekCurrent); err != nil {
		s.NewError(ctx, v2rayErrors.New("failed to skip padding in UDP packet").Base(err))
		packet.Release(); return nil
	}
	addr, port, err := AddrParser.ReadAddressPort(nil, payloadReader)
	if err != nil {
		s.NewError(ctx, v2rayErrors.New("failed to read address and port from UDP packet").Base(err))
		packet.Release(); return nil
	}
	destination := v2rayNet.UDPDestination(addr, port) 
	actualPayload := buf.New()
	defer actualPayload.Release()
	_, err = actualPayload.ReadFrom(payloadReader)
	if err != nil {
		s.NewError(ctx, v2rayErrors.New("failed to read actual payload from UDP packet").Base(err))
		return nil // Return nil as payload buffer is released by defer
	}
	ctx = context.WithValue(ctx, "ClientSessionID", clientSessionID)
	ctx = context.WithValue(ctx, "ClientPacketID", clientPacketID)
	err = s.protocolHandler.HandleUDPPacket(ctx, actualPayload, source, destination, dispatcher)
	if err != nil {
		s.NewError(ctx, v2rayErrors.New("inbound handler failed to process UDP packet").Base(err))
		packet.Release(); return nil // Return nil as original packet needs releasing
	}
	packet.Release()
	return nil
}

// EncryptUDPResponse remains the same as the previously corrected version
func (s *Shadowsocks2022ServiceImpl) EncryptUDPResponse(ctx context.Context, payloadToEncrypt *buf.Buffer, clientOriginalSessionID [8]byte, originalDest v2rayNet.Destination) (*buf.Buffer, error) {
	serverSessionID := [8]byte{}
	if _, err := rand.Read(serverSessionID[:]); err != nil {
		return nil, v2rayErrors.New("failed to generate server session ID for UDP response").Base(err)
	}
	serverPacketID := uint64(0) 

	metadataAndPayloadBuf := buf.New()
	defer metadataAndPayloadBuf.Release()

	if s.method == "2022-blake3-chacha20-poly1305" {
		metadataAndPayloadBuf.Write(serverSessionID[:])
		metadataAndPayloadBuf.Write(binary.BigEndian.AppendUint64(nil, serverPacketID))
	}

	paddingLen := 0 
	respMainHeader := struct {
		Type                byte
		Timestamp           uint64
		ClientOrigSessionID [8]byte
		PaddingLength       uint16 `struc:"sizeof=Padding"`
		Padding             []byte
	}{
		Type:                UDPHeaderTypeServerToClientStream,
		Timestamp:           uint64(time.Now().Unix()),
		ClientOrigSessionID: clientOriginalSessionID,
		PaddingLength:       uint16(paddingLen),
		Padding:             make([]byte, paddingLen),
	}
	if err := struc.Pack(metadataAndPayloadBuf, &respMainHeader); err != nil {
		return nil, v2rayErrors.New("failed to pack UDP response main header").Base(err)
	}
	if err := AddrParser.WriteAddressPort(metadataAndPayloadBuf, originalDest.Address, originalDest.Port); err != nil {
		return nil, v2rayErrors.New("failed to write original destination to UDP response").Base(err)
	}
	if _, err := metadataAndPayloadBuf.Write(payloadToEncrypt.Bytes()); err != nil {
		return nil, v2rayErrors.New("failed to write actual data to UDP response main payload").Base(err)
	}

	finalResponsePacket := buf.New()

	if s.method == "2022-blake3-chacha20-poly1305" {
		packetNonce := make([]byte, UDPChaCha20PacketNonceSize)
		if _, err := rand.Read(packetNonce); err != nil {
			finalResponsePacket.Release(); return nil, v2rayErrors.New("failed to generate ChaCha20 packet nonce for UDP response").Base(err)
		}
		finalResponsePacket.Write(packetNonce)
		aead, err := s.methodInfo.New(s.key) 
		if err != nil {
			finalResponsePacket.Release(); return nil, v2rayErrors.New("failed to create ChaCha20 AEAD for UDP response").Base(err)
		}
		encryptedPayloadBytes := finalResponsePacket.Extend(metadataAndPayloadBuf.Len() + int32(aead.Overhead()))
		aead.Seal(encryptedPayloadBytes[:0], packetNonce, metadataAndPayloadBuf.Bytes(), nil) 
	} else { 
		cleartextIndependentHeaderBytes := make([]byte, UDPPacketHeaderSize)
		copy(cleartextIndependentHeaderBytes[0:8], serverSessionID[:])
		binary.BigEndian.PutUint64(cleartextIndependentHeaderBytes[8:16], serverPacketID)
		headerCipher, err := aes.NewCipher(s.key) 
		if err != nil {
			finalResponsePacket.Release(); return nil, v2rayErrors.New("failed to create AES cipher for UDP response independent header").Base(err)
		}
		encryptedIndependentHeader := finalResponsePacket.Extend(UDPPacketHeaderSize)
		headerCipher.Encrypt(encryptedIndependentHeader, cleartextIndependentHeaderBytes)
		
		aeadKey, err := SessionKey(s.key, serverSessionID[:], s.methodInfo.KeySize)
		if err != nil {
		    finalResponsePacket.Release(); return nil, v2rayErrors.New("failed to derive AEAD key for UDP response payload").Base(err)
		}
		aead, err := s.methodInfo.New(aeadKey)
		if err != nil {
			finalResponsePacket.Release(); return nil, v2rayErrors.New("failed to create AEAD for UDP response payload").Base(err)
		}
		nonce := make([]byte, UDPAEADNonceSize)
		copy(nonce[0:4], cleartextIndependentHeaderBytes[4:8])  
		copy(nonce[4:12], cleartextIndependentHeaderBytes[8:16]) 
		encryptedMainPayloadBytes := finalResponsePacket.Extend(metadataAndPayloadBuf.Len() + int32(aead.Overhead()))
		aead.Seal(encryptedMainPayloadBytes[:0], nonce, metadataAndPayloadBuf.Bytes(), nil)
	}

	return finalResponsePacket, nil
}

// Ss2022WrappedConnection definition reverted to support two-stage header and separate AEAD contexts
type Ss2022WrappedConnection struct {
	internet.Connection
	originalPSK         []byte     
	methodInfo          MethodInfo 
	clientSalt          []byte      
	c2sAEAD             cipher.AEAD 
	decryptNonceCounter uint64      
	serverSalt          []byte      
	s2cAEAD             cipher.AEAD 
	s2cEncryptNonceCounter uint64   
	decryptBuffer       *buf.Buffer
	headerRead          bool 
	responseHeaderSent  bool 
}

// Read reads data from the connection, decrypting Shadowsocks 2022 chunks using c2sAEAD.
func (wc *Ss2022WrappedConnection) Read(p []byte) (n int, err error) {
	if wc.decryptBuffer != nil && wc.decryptBuffer.Len() > 0 {
		n, err := wc.decryptBuffer.Read(p)
		if wc.decryptBuffer.Len() == 0 {
			wc.decryptBuffer.Release()
			wc.decryptBuffer = nil
		}
		return n, err
	}

	encryptedLenBytes := make([]byte, 2+wc.methodInfo.TagSize)
	if _, err := io.ReadFull(wc.Connection, encryptedLenBytes); err != nil {
		if err == io.EOF { return 0, io.EOF }
		return 0, v2rayErrors.New("failed to read encrypted chunk length").Base(err)
	}

	nonce := make([]byte, wc.methodInfo.NonceSize)
	binary.BigEndian.PutUint64(nonce[wc.methodInfo.NonceSize-8:], wc.decryptNonceCounter)

	decryptedLenBytes, err := wc.c2sAEAD.Open(nil, nonce, encryptedLenBytes, nil)
	if err != nil {
		return 0, v2rayErrors.New("failed to decrypt chunk length").Base(err)
	}
	chunkPayloadLen := binary.BigEndian.Uint16(decryptedLenBytes)

	encryptedChunkPayloadAndTag := make([]byte, int(chunkPayloadLen)+wc.methodInfo.TagSize)
	if _, err := io.ReadFull(wc.Connection, encryptedChunkPayloadAndTag); err != nil {
		if err == io.EOF { return 0, io.EOF }
		return 0, v2rayErrors.New("failed to read encrypted chunk payload and tag").Base(err)
	}

	decryptedChunkPayload, err := wc.c2sAEAD.Open(nil, nonce, encryptedChunkPayloadAndTag, nil)
	if err != nil {
		return 0, v2rayErrors.New("failed to decrypt chunk payload").Base(err)
	}
	wc.decryptNonceCounter++

	n = copy(p, decryptedChunkPayload)
	if n < len(decryptedChunkPayload) {
		wc.decryptBuffer = buf.New()
		wc.decryptBuffer.Write(decryptedChunkPayload[n:])
	}
	return n, nil
}

// Write writes data to the connection, encrypting it using the two-stage header format logic.
func (wc *Ss2022WrappedConnection) Write(p []byte) (n int, err error) {
	if !wc.responseHeaderSent {
		serverSalt := make([]byte, wc.methodInfo.KeySize)
		if _, errRand := io.ReadFull(rand.Reader, serverSalt); errRand != nil {
			return 0, v2rayErrors.New("failed to generate server salt for response").Base(errRand)
		}
		if _, errWrite := wc.Connection.Write(serverSalt); errWrite != nil {
			return 0, v2rayErrors.New("failed to write server salt").Base(errWrite)
		}
		wc.serverSalt = serverSalt 
		s2cSessionKey, errKey := SessionKey(wc.originalPSK, wc.serverSalt, wc.methodInfo.KeySize)
		if errKey != nil {
		    return 0, v2rayErrors.New("failed to derive S2C session key").Base(errKey)
		}
		s2cAEADInstance, errAEAD := wc.methodInfo.New(s2cSessionKey)
		if errAEAD != nil {
			return 0, v2rayErrors.New("failed to create S2C AEAD for response").Base(errAEAD)
		}
		wc.s2cAEAD = s2cAEADInstance
		wc.s2cEncryptNonceCounter = 0 

		responseHeader := TCPResponseFixedHeader{
			Type:                 TCPHeaderTypeServerToClientStream,
			Timestamp:            uint64(time.Now().Unix()),
			RequestSalt:          wc.clientSalt, 
			InitialPayloadLength: 0,             
		}
		headerBytes := bytes.NewBuffer(make([]byte, 0, 1+8+len(wc.clientSalt)+2))
		binary.Write(headerBytes, binary.BigEndian, responseHeader.Type)
		binary.Write(headerBytes, binary.BigEndian, responseHeader.Timestamp)
		headerBytes.Write(responseHeader.RequestSalt)
		binary.Write(headerBytes, binary.BigEndian, responseHeader.InitialPayloadLength)

		headerPayloadLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(headerPayloadLenBytes, uint16(headerBytes.Len()))
		nonce := make([]byte, wc.methodInfo.NonceSize)
		binary.BigEndian.PutUint64(nonce[wc.methodInfo.NonceSize-8:], wc.s2cEncryptNonceCounter)

		encryptedHeaderPayloadLen := wc.s2cAEAD.Seal(nil, nonce, headerPayloadLenBytes, nil)
		if _, errWrite := wc.Connection.Write(encryptedHeaderPayloadLen); errWrite != nil {
			return 0, v2rayErrors.New("failed to write encrypted response header payload length").Base(errWrite)
		}
		encryptedHeaderPayload := wc.s2cAEAD.Seal(nil, nonce, headerBytes.Bytes(), nil)
		if _, errWrite := wc.Connection.Write(encryptedHeaderPayload); errWrite != nil {
			return 0, v2rayErrors.New("failed to write encrypted response header payload").Base(errWrite)
		}
		wc.s2cEncryptNonceCounter++ 
		wc.responseHeaderSent = true
	}

	totalWritten := 0
	remainingData := p
	chunkSize := 4096 
	for len(remainingData) > 0 {
		currentChunkSize := chunkSize
		if currentChunkSize > len(remainingData) {
			currentChunkSize = len(remainingData)
		}
		payloadChunk := remainingData[:currentChunkSize]
		payloadChunkLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(payloadChunkLenBytes, uint16(len(payloadChunk)))
		nonce := make([]byte, wc.methodInfo.NonceSize)
		binary.BigEndian.PutUint64(nonce[wc.methodInfo.NonceSize-8:], wc.s2cEncryptNonceCounter) 
		encryptedPayloadChunkLen := wc.s2cAEAD.Seal(nil, nonce, payloadChunkLenBytes, nil) 
		if _, errWrite := wc.Connection.Write(encryptedPayloadChunkLen); errWrite != nil {
			return totalWritten, v2rayErrors.New("failed to write encrypted data chunk length").Base(errWrite)
		}
		encryptedPayloadChunk := wc.s2cAEAD.Seal(nil, nonce, payloadChunk, nil) 
		if _, errWrite := wc.Connection.Write(encryptedPayloadChunk); errWrite != nil {
			return totalWritten, v2rayErrors.New("failed to write encrypted data chunk").Base(errWrite)
		}
		wc.s2cEncryptNonceCounter++ 
		totalWritten += len(payloadChunk)
		remainingData = remainingData[currentChunkSize:]
	}
	return totalWritten, nil
}

// Close closes the underlying connection.
func (wc *Ss2022WrappedConnection) Close() error { return wc.Connection.Close() }
func (wc *Ss2022WrappedConnection) LocalAddr() net.Addr { return wc.Connection.LocalAddr() } 
func (wc *Ss2022WrappedConnection) RemoteAddr() net.Addr { return wc.Connection.RemoteAddr() } 
func (wc *Ss2022WrappedConnection) SetDeadline(t time.Time) error { return wc.Connection.SetDeadline(t) }
func (wc *Ss2022WrappedConnection) SetReadDeadline(t time.Time) error { return wc.Connection.SetReadDeadline(t) }
func (wc *Ss2022WrappedConnection) SetWriteDeadline(t time.Time) error { return wc.Connection.SetWriteDeadline(t) }

func (wc *Ss2022WrappedConnection) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer := buf.New()
	_, err := wc.Read(buffer.Extend(buf.Size))
	if err != nil {
		buffer.Release()
		return nil, err
	}
	var mb buf.MultiBuffer 
	mb = append(mb, buffer)
	return mb, nil
}

func (wc *Ss2022WrappedConnection) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, buffer := range mb {
		_, err := wc.Write(buffer.Bytes())
		buffer.Release()
		if err != nil {
			buf.ReleaseMulti(mb) 
			return err
		}
	}
	return nil
}

// readAndDecryptHeader reads and decrypts the initial header using the two-stage format.
func (wc *Ss2022WrappedConnection) readAndDecryptHeader(ctx context.Context) (v2rayNet.Destination, *buf.Buffer, error) {
	// Part 1: Read and decrypt the fixed-length header 
	encryptedFixedHeaderPayloadLenBytes := make([]byte, 2+wc.methodInfo.TagSize)
	if _, err := io.ReadFull(wc.Connection, encryptedFixedHeaderPayloadLenBytes); err != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to read encrypted length of fixed header payload").Base(err)
	}
	nonceFixedHeader := make([]byte, wc.methodInfo.NonceSize)
	binary.BigEndian.PutUint64(nonceFixedHeader[wc.methodInfo.NonceSize-8:], wc.decryptNonceCounter) 
	decryptedFixedHeaderPayloadLenBytes, err := wc.c2sAEAD.Open(nil, nonceFixedHeader, encryptedFixedHeaderPayloadLenBytes, nil)
	if err != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to decrypt fixed header payload length").Base(err)
	}
	fixedHeaderPayloadLen := binary.BigEndian.Uint16(decryptedFixedHeaderPayloadLenBytes)
	if fixedHeaderPayloadLen != (1 + 8 + 2) { 
		return v2rayNet.Destination{}, nil, v2rayErrors.New("decrypted fixed header payload length mismatch: expected 11, got ", fixedHeaderPayloadLen)
	}
	encryptedFixedHeaderPayload := make([]byte, int(fixedHeaderPayloadLen)+wc.methodInfo.TagSize)
	var readErr error 
	if _, readErr = io.ReadFull(wc.Connection, encryptedFixedHeaderPayload); readErr != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to read encrypted fixed header payload").Base(readErr)
	}
	decryptedFixedHeaderPayload, err := wc.c2sAEAD.Open(nil, nonceFixedHeader, encryptedFixedHeaderPayload, nil)
	if err != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to decrypt fixed header payload").Base(err)
	}
	wc.decryptNonceCounter++

	fixedHeaderReader := bytes.NewReader(decryptedFixedHeaderPayload)
	fixedHeader := TCPRequestFixedHeader{}
	if readErr = binary.Read(fixedHeaderReader, binary.BigEndian, &fixedHeader.Type); readErr != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to read Type from fixed header").Base(readErr)
	}
	if fixedHeader.Type != TCPHeaderTypeClientToServerStream {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("invalid Type in fixed header: expected ", TCPHeaderTypeClientToServerStream, " got ", fixedHeader.Type)
	}
	if readErr = binary.Read(fixedHeaderReader, binary.BigEndian, &fixedHeader.Timestamp); readErr != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to read Timestamp from fixed header").Base(readErr)
	}
	if readErr = binary.Read(fixedHeaderReader, binary.BigEndian, &fixedHeader.VariablePayloadLength); readErr != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to read VariablePayloadLength from fixed header").Base(readErr)
	}

	// Part 2: Read and decrypt the variable-length payload
	encryptedVariablePayloadLenBytes := make([]byte, 2+wc.methodInfo.TagSize)
	if _, readErr = io.ReadFull(wc.Connection, encryptedVariablePayloadLenBytes); readErr != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to read encrypted length of variable payload").Base(readErr)
	}
	nonceVariablePayload := make([]byte, wc.methodInfo.NonceSize)
	binary.BigEndian.PutUint64(nonceVariablePayload[wc.methodInfo.NonceSize-8:], wc.decryptNonceCounter)
	decryptedVariablePayloadLenBytes, err := wc.c2sAEAD.Open(nil, nonceVariablePayload, encryptedVariablePayloadLenBytes, nil)
	if err != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to decrypt variable payload length").Base(err)
	}
	variablePayloadActualLen := binary.BigEndian.Uint16(decryptedVariablePayloadLenBytes)
	if variablePayloadActualLen != fixedHeader.VariablePayloadLength {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("variable payload length mismatch: header said ", fixedHeader.VariablePayloadLength, ", actual was ", variablePayloadActualLen)
	}
	encryptedVariablePayload := make([]byte, int(variablePayloadActualLen)+wc.methodInfo.TagSize)
	if _, readErr = io.ReadFull(wc.Connection, encryptedVariablePayload); readErr != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to read encrypted variable payload").Base(readErr)
	}
	decryptedVariablePayload, err := wc.c2sAEAD.Open(nil, nonceVariablePayload, encryptedVariablePayload, nil)
	if err != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to decrypt variable payload").Base(err)
	}
	wc.decryptNonceCounter++
	wc.headerRead = true

	variablePayloadReader := bytes.NewReader(decryptedVariablePayload)
	destAddress, destPort, readErr := AddrParser.ReadAddressPort(nil, variablePayloadReader)
	if readErr != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to read destination address from variable payload").Base(readErr)
	}
	destination := v2rayNet.TCPDestination(destAddress, destPort)
	var paddingLength uint16
	if readErr = binary.Read(variablePayloadReader, binary.BigEndian, &paddingLength); readErr != nil {
		return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to read padding length from variable payload").Base(readErr)
	}
	if paddingLength > 0 {
		if _, readErr = variablePayloadReader.Seek(int64(paddingLength), io.SeekCurrent); readErr != nil {
			return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to skip padding in variable payload").Base(readErr)
		}
	}
	remainingBuffer := buf.New()
	if variablePayloadReader.Len() > 0 {
		initialData := make([]byte, variablePayloadReader.Len())
		if _, readErr = variablePayloadReader.Read(initialData); readErr != nil {
			remainingBuffer.Release(); return v2rayNet.Destination{}, nil, v2rayErrors.New("failed to read initial data from variable payload").Base(readErr)
		}
		remainingBuffer.Write(initialData)
	}
	return destination, remainingBuffer, nil
}