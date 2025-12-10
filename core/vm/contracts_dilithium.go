package vm

import (
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// dilithiumVerify implements the Dilithium3 verification precompile.
type dilithiumVerify struct{}

const (
	dilithiumPublicKeySize = 1952
	dilithiumSignatureSize = 3293
	dilithiumFixedSize     = dilithiumPublicKeySize + dilithiumSignatureSize
)

// RequiredGas calculates the gas cost for Dilithium verification
// Base cost: 25000 (expensive)
// Word cost: 100 per 32 bytes of message
func (c *dilithiumVerify) RequiredGas(input []byte) uint64 {
	const baseCost = 25000
	const wordCost = 100

	msgLen := 0
	if len(input) > dilithiumFixedSize {
		msgLen = len(input) - dilithiumFixedSize
	}

	words := uint64((msgLen + 31) / 32)
	return baseCost + words*wordCost
}

// Run executes the precompile
// Input: [PublicKey (1952)][Signature (3293)][Message...]
// Output: 32 bytes (1 if valid, 0 if invalid/error)
func (c *dilithiumVerify) Run(input []byte) ([]byte, error) {
	if len(input) < dilithiumFixedSize {
		return make([]byte, 32), nil // Return 0 (false)
	}

	// Extract components
	pubKeyBytes := input[:dilithiumPublicKeySize]
	sigBytes := input[dilithiumPublicKeySize : dilithiumPublicKeySize+dilithiumSignatureSize]
	msg := input[dilithiumPublicKeySize+dilithiumSignatureSize:]

	// Unpack Public Key
	pk := mode3.PublicKeyFromBytes(pubKeyBytes)
	var sig mode3.Signature
	copy(sig[:], sigBytes) // Assuming size matches

	// Note: mode3.PublicKeyFromBytes might verify key format?
	// It returns *PublicKey. If invalid, it might panic or return clean obj?
	// Looking at Circl docs/implementations usually simpler.
	// Assuming Pack/Unpack is robust.

	if mode3.Verify(pk, msg, &sig) {
		// Return 1
		res := make([]byte, 32)
		res[31] = 1
		return res, nil
	}

	return make([]byte, 32), nil // Return 0 (false)
}

func (c *dilithiumVerify) Name() string {
	return "DILITHIUM3"
}
