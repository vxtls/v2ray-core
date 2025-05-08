package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	commonErrors "github.com/v2fly/v2ray-core/v5/common/errors"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/shared"
)

func NewAES128GCMMethod() *AES128GCMMethod {
	return &AES128GCMMethod{}
}

type AES128GCMMethod struct{}

// Name implements Method.Name
func (a AES128GCMMethod) Name() string {
	return "2022-blake3-aes-128-gcm"
}

func (a AES128GCMMethod) GetSessionSubKeyAndSaltLength() int {
	return 16
}

func (a AES128GCMMethod) GetStreamAEAD(sessionSubKey []byte) (cipher.AEAD, error) {
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

func (a AES128GCMMethod) EncryptEIHPart(identityKey []byte, pskHashToEncrypt []byte, outputBuffer []byte) error {
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

func (a AES128GCMMethod) GetUDPClientProcessor(ipsk [][]byte, psk []byte) (shared.UDPClientPacketProcessor, error) {

	methodInfo, ok := shadowsocks2022.MethodMap[a.Name()]
	if !ok {
		return nil, commonErrors.New("UDPClientProcessor: method info not found for ", a.Name())
	}

	var eihGeneratorFunc func([]byte) shared.ExtensibleIdentityHeaders // Corrected type to shared.ExtensibleIdentityHeaders
	if len(ipsk) > 0 {
		newError("UDP EIH for SS2022 client not fully aligned with sing-shadowsocks yet. EIH generation might be nil.").AtWarning().WriteToLog()
		// Placeholder for actual EIH generator logic if ipsk is present
		// For now, eihGeneratorFunc remains nil if ipsk is not handled for EIH.
	}

	requestBlockCipher, err := aes.NewCipher(psk)
	if err != nil {
		return nil, commonErrors.New("failed to create request block cipher for UDP").Base(err)
	}
	responseBlockCipher, err := aes.NewCipher(psk) // Assuming same key for request and response path for now
	if err != nil {
		return nil, commonErrors.New("failed to create response block cipher for UDP").Base(err)
	}

	mainAEADFunc := func(key []byte) cipher.AEAD {
		if err != nil {
			newError("failed to create AEAD in mainAEADFunc for UDP: ", err).AtError().WriteToLog()
			return nil
		}
		return aead
	}

	processor := NewAESUDPClientPacketProcessor(requestBlockCipher, responseBlockCipher, mainAEADFunc, eihGeneratorFunc)
	return processor, nil
}

func newError(v ...interface{}) *commonErrors.Error {
	return commonErrors.New(v...)
}
