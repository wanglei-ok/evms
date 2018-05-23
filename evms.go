// Ethereum Verified Message Signature
package evms

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	NormalSignHasherId     = 1
	RawSignHasherId        = 2
	GethPrefixSignHasherId = 3
)

func normalSignHasher(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

func rawSignHasher(data []byte) []byte {
	return crypto.Keccak256([]byte(data))
}

func gethPrefixSignHasher(data []byte) []byte {
	return normalSignHasher(rawSignHasher(data))
}

func has0xPrefix(input string) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}

var signhashers = []struct {
	id int
	fn func([]byte) []byte
}{
	{1, normalSignHasher},
	{2, rawSignHasher},
	{3, gethPrefixSignHasher},
}

func VerifyMessage(addr, sig, msg string) (error, int) {
	addressStr := addr
	signatureHex := sig
	message := []byte(msg)

	if !common.IsHexAddress(addressStr) {
		return fmt.Errorf("Invalid address: %s", addressStr), 0
	}
	address := common.HexToAddress(addressStr)

	var signature []byte
	var err error
	if has0xPrefix(signatureHex) {
		signature, err = hex.DecodeString(signatureHex[2:])
	} else {
		signature, err = hex.DecodeString(signatureHex)
	}

	if err != nil {
		return fmt.Errorf("Signature encoding is not hexadecimal: %v", err), 0
	}

	if len(signature) != 65 {
		return fmt.Errorf("Signature must be 65 bytes long"), 0
	}
	if signature[64] == 27 || signature[64] == 28 {
		signature[64] -= 27 // Transform yellow paper V from 27/28 to 0/1
	}

	for _, sh := range signhashers {
		recoveredPubkey, err := crypto.SigToPub(sh.fn(message), signature)
		if err != nil || recoveredPubkey == nil {
			return fmt.Errorf("Signature verification failed: %v", err), 0
		}

		recoveredAddress := crypto.PubkeyToAddress(*recoveredPubkey)
		if address == recoveredAddress {
			return nil, sh.id
		}
	}

	return fmt.Errorf("The Signature Message Verification Failed."), 0
}

func IsValidAddress(address string) bool {
	return common.IsHexAddress(address)
}
