package txscript

import "github.com/btcsuite/btcd/btcec"

var LibsecpAvailable bool
var LibsecpVerify func(pkey, sign, hash []byte) bool

func init() {
	if btcec.LibsecpAvailable {
		LibsecpVerify = func(pubKey, sigBytes, hash []byte) bool {
			if len(pubKey) == 0 || len(sigBytes) == 0 {
				return false
			}
			return btcec.LibsecpVerify(pubKey, sigBytes, hash) == 1
		}
	}
}
