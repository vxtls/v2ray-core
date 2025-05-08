package crypto

import (
	"crypto/subtle"
	"io"

	commonErrors "github.com/v2fly/v2ray-core/v5/common/errors"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/shared"
	"github.com/v2fly/struc"
	"lukechampine.com/blake3"
)

func NewAESEIH(size int) *aesEIH {
	return &aesEIH{length: size}
}

func NewAESEIHWithData(size int, eih [][aesEIHSize]byte) *aesEIH {
	return &aesEIH{length: size, eih: eih}
}

const aesEIHSize = 16

type aesEIH struct {
	eih    [][aesEIHSize]byte
	length int
}

func (a *aesEIH) Pack(p []byte, opt *struc.Options) (int, error) {
	var totalCopy int
	for i := 0; i < a.length; i++ {
		n := copy(p[aesEIHSize*i:aesEIHSize*(i+1)], a.eih[i][:])
		if n != 16 {
			return 0, commonErrors.New("failed to pack aesEIH")
		}
		totalCopy += n
	}
	return totalCopy, nil
}

func (a *aesEIH) Unpack(r io.Reader, length int, opt *struc.Options) error {
	a.eih = make([][aesEIHSize]byte, a.length)
	for i := 0; i < a.length; i++ {
		n, err := r.Read(a.eih[i][:])
		if err != nil {
			return commonErrors.New("failed to unpack aesEIH").Base(err)
		}
		if n != aesEIHSize {
			return commonErrors.New("failed to unpack aesEIH")
		}
	}
	return nil
}

func (a *aesEIH) Size(opt *struc.Options) int {
	return a.length * aesEIHSize
}

func (a *aesEIH) String() string {
	return ""
}

const aesEIHPskHashSize = 16

type aesEIHGenerator struct {
	ipsk     [][]byte
	ipskHash [][aesEIHPskHashSize]byte
	psk      []byte
	pskHash  [aesEIHPskHashSize]byte
	length   int
}

func NewAESEIHGeneratorContainer(size int, effectivePsk []byte, ipsk [][]byte) *aesEIHGenerator {
	var ipskHash [][aesEIHPskHashSize]byte
	for _, v := range ipsk {
		hash := blake3.Sum512(v)
		ipskHash = append(ipskHash, [aesEIHPskHashSize]byte(hash[:16]))
	}
	pskHashFull := blake3.Sum512(effectivePsk)
	pskHash := [aesEIHPskHashSize]byte(pskHashFull[:16])
	return &aesEIHGenerator{length: size, ipsk: ipsk, ipskHash: ipskHash, psk: effectivePsk, pskHash: pskHash}
}

func (a *aesEIHGenerator) GenerateEIH(derivation shared.KeyDerivation, method shared.Method, salt []byte) (shared.ExtensibleIdentityHeaders, error) {
	return a.generateEIHWithMask(method, salt, nil)
}

func (a *aesEIHGenerator) GenerateEIHUDP(method shared.Method, mask []byte) (shared.ExtensibleIdentityHeaders, error) {
	return a.generateEIHWithMask(method, nil, mask)
}

// Removed derivation KeyDerivation parameter
func (a *aesEIHGenerator) generateEIHWithMask(method shared.Method, salt, mask []byte) (shared.ExtensibleIdentityHeaders, error) {
	eih := make([][16]byte, a.length)
	current := a.length - 1
	currentPskHash := a.pskHash // This is [16]byte
	identityKeyLen := method.GetSessionSubKeyAndSaltLength()

	for {
		finalIdentityKey := make([]byte, identityKeyLen)
		currentIterIPSK := a.ipsk[current]

		if mask == nil { // TCP-like path, use salt for derivation
			if salt == nil {
				return nil, commonErrors.New("salt cannot be nil for TCP EIH generation")
			}
			keyMaterialForDerivation := make([]byte, len(currentIterIPSK)+len(salt))
			copy(keyMaterialForDerivation, currentIterIPSK)
			copy(keyMaterialForDerivation[len(currentIterIPSK):], salt)
			blake3.DeriveKey(finalIdentityKey, "shadowsocks 2022 identity subkey", keyMaterialForDerivation)
		} else { // UDP-like path, ipsk is used more directly (ensure length matches)
			if len(currentIterIPSK) != identityKeyLen {
				if len(currentIterIPSK) >= identityKeyLen {
					copy(finalIdentityKey, currentIterIPSK[:identityKeyLen])
				} else {
					copy(finalIdentityKey, currentIterIPSK)
				}
			} else {
				copy(finalIdentityKey, currentIterIPSK)
			}
		}

		eih[current] = [16]byte{} // Ensure it's a new 16-byte array for the output
		
		tempPskHash := currentPskHash 
		if mask != nil {
			xorInput := make([]byte, 16)
			copy(xorInput, tempPskHash[:])
			subtle.XORBytes(xorInput, xorInput, mask[:16]) 
			subtle.XORBytes(tempPskHash[:], tempPskHash[:], mask[:16]) 
		}

		err := method.EncryptEIHPart(finalIdentityKey, tempPskHash[:], eih[current][:])
		if err != nil {
			return nil, commonErrors.New("failed to encrypt EIH part").Base(err)
		}

		current--
		if current < 0 {
			break
		}
		currentPskHash = a.ipskHash[current] 
	}
	return NewAESEIHWithData(a.length, eih), nil
}
