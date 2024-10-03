package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestPrivateSign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("sup")

	sig := privKey.Sign(msg)
	assert.True(t, sig.Verify(pubKey, msg))

	// Invalid message test
	assert.False(t, sig.Verify(pubKey, []byte("Whats up")))

	// Invalid pubkey test
	invalidPrivateKey := GeneratePrivateKey()
	invalidPublicKey := invalidPrivateKey.Public()
	assert.False(t, sig.Verify(invalidPublicKey, msg))
}

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))
	fmt.Println(address)
}

func TestNewPrivateKeyFromString(t *testing.T) {
	seed := "fdc27647e5969ae7975a8e2b128b15097e4a66789d8e57d5a7c6b3a8f6b6d5c3"
	privKey := NewPrivateKeyFromString(seed)

	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
}
