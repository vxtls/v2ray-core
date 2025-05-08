package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	commonErrors "github.com/v2fly/v2ray-core/v5/common/errors"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/shared"
)

func NewAES256GCMMethod() *AES256GCMMethod {
	return &AES256GCMMethod{}
}

type AES256GCMMethod struct{}

// Name implements Method.Name
func (a AES256GCMMethod) Name() string {
	return "2022-blake3-aes-256-gcm"
}

func (a AES256GCMMethod) GetSessionSubKeyAndSaltLength() int {
	return 32
}

func (a AES256GCMMethod) GetStreamAEAD(sessionSubKey []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(sessionSubKey)
	if err != nil {
		return nil, commonErrors.New("failed to create AES cipher").Base(err)
	}
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, commonErrors.New("failed to create AES-GCM AEAD").Base(err)
	}
	return aead, nil
}

func (a AES256GCMMethod) EncryptEIHPart(identityKey []byte, pskHashToEncrypt []byte, outputBuffer []byte) error {
	block, err := aes.NewCipher(identityKey)
	if err != nil {
		return commonErrors.New("failed to create AES cipher for EIH part").Base(err)
	}
	if len(pskHashToEncrypt) != aes.BlockSize || len(outputBuffer) != aes.BlockSize {
		return commonErrors.New("invalid input/output buffer size for EIH encryption")
	}
	block.Encrypt(outputBuffer, pskHashToEncrypt)
	return nil
}

func (a AES256GCMMethod) GetUDPClientProcessor(ipsk [][]byte, psk []byte) (shared.UDPClientPacketProcessor, error) {
	methodInfo, ok := shadowsocks2022.MethodMap[a.Name()]
	if !ok {
		return nil, commonErrors.New("UDPClientProcessor: method info not found for ", a.Name())
	}

	var eihGeneratorFunc func([]byte) shared.ExtensibleIdentityHeaders
	if len(ipsk) > 0 {
		newError("UDP EIH for SS2022 client not fully aligned with sing-shadowsocks yet. EIH generation might be nil.").AtWarning().WriteToLog()
	}

	requestBlockCipher, err := aes.NewCipher(psk)
	if err != nil {
		return nil, commonErrors.New("failed to create request block cipher for UDP").Base(err)
	}
	responseBlockCipher, err := aes.NewCipher(psk)
	if err != nil {
		return nil, commonErrors.New("failed to create response block cipher for UDP").Base(err)
	}

	mainAEADFunc := func(key []byte) cipher.AEAD {
		aead, err := methodInfo.New(key)
		if err != nil {

			newError("failed to create AEAD in mainAEADFunc for UDP (aes256gcm): ", err).AtError().WriteToLog()
			return nil
		}
		return aead
	}

	processor := NewAESUDPClientPacketProcessor(requestBlockCipher, responseBlockCipher, mainAEADFunc, eihGeneratorFunc)
	return processor, nil
}