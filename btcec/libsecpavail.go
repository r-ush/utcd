package btcec

// variables that let us know if the libsecp256k1 library is available for use.
var (
	LibsecpAvailable bool
	LibsecpVerify    func(pkey, sign, hash []byte) int
)
