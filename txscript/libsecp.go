package txscript

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/sipasec"
)

var LibsecpAvailable bool

func verify() bool {
	key, _ := hex.DecodeString("020eaebcd1df2df853d66ce0e1b0fda07f67d1cabefde98514aad795b86a6ea66d")
	sig, _ := hex.DecodeString("3045022100fe00e013c244062847045ae7eb73b03fca583e9aa5dbd030a8fd1c6dfcf11b1002207d0d04fed8fa1e93007468d5a9e134b0a7023b6d31db4e50942d43a250f4d07c01")
	has, _ := hex.DecodeString("3382219555ddbb5b00e0090f469e590ba1eae03c7f28ab937de330aa60294ed6")
	return sipasec.ECVerify(key, sig, has) == 1
}

func init() {
	if verify() {
		LibsecpAvailable = true
	}
}
