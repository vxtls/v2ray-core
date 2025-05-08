package crypto

import (
	"crypto/cipher"
	"golang.org/x/crypto/chacha20poly1305"

	commonErrors "github.com/v2fly/v2ray-core/v5/common/errors"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/shared"
)

func NewChaCha20Poly1305Method() *ChaCha20Poly1305Method {
	return &ChaCha20Poly1305Method{}
}

type ChaCha20Poly1305Method struct{}

func (m *ChaCha20Poly1305Method) Name() string {
	return "2022-blake3-chacha20-poly1305"
}

func (m *ChaCha20Poly1305Method) GetSessionSubKeyAndSaltLength() int {
	return 32
}

func (m *ChaCha20Poly1305Method) GetStreamAEAD(sessionSubKey []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(sessionSubKey)
}

func (m *ChaCha20Poly1305Method) EncryptEIHPart(identityKey []byte, pskHashToEncrypt []byte, outputBuffer []byte) error {
	return commonErrors.New("EIH not typically used with ChaCha20Poly1305 in this context or not implemented")
}

func (m *ChaCha20Poly1305Method) GetUDPClientProcessor(ipsk [][]byte, psk []byte) (shared.UDPClientPacketProcessor, error) {
	methodInfo, ok := shadowsocks2022.MethodMap[m.Name()]
	if !ok {
		return nil, commonErrors.New("UDPClientProcessor: method info not found for ", m.Name())
	}
	return NewChaCha20UDPClientPacketProcessor(psk, &methodInfo)
}
