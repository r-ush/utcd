// Copyright (c) 2013-2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

const (
	// MaxDataCarrierSize is the maximum number of bytes allowed in pushed
	// data to be considered a nulldata transaction
	MaxDataCarrierSize = 80

	// StandardVerifyFlags are the script flags which are used when
	// executing transaction scripts to enforce additional checks which
	// are required for the script to be considered standard.  These checks
	// help reduce issues related to transaction malleability as well as
	// allow pay-to-script hash transactions.  Note these flags are
	// different than what is required for the consensus rules in that they
	// are more strict.
	//
	// TODO: This definition does not belong here.  It belongs in a policy
	// package.
	StandardVerifyFlags = ScriptBip16 |
		ScriptVerifyDERSignatures |
		ScriptVerifyStrictEncoding |
		ScriptVerifyMinimalData |
		ScriptStrictMultiSig |
		ScriptDiscourageUpgradableNops |
		ScriptVerifyCleanStack |
		ScriptVerifyNullFail |
		ScriptVerifyCheckLockTimeVerify |
		ScriptVerifyCheckSequenceVerify |
		ScriptVerifyLowS |
		ScriptStrictMultiSig |
		ScriptVerifyWitness |
		ScriptVerifyDiscourageUpgradeableWitnessProgram |
		ScriptVerifyMinimalIf |
		ScriptVerifyWitnessPubKeyType
)

// ScriptClass is an enumeration for the list of standard types of script.
type ScriptClass byte

// Classes of script payment known about in the blockchain.
const (
	NonStandardTy         ScriptClass = iota // None of the recognized forms.
	PubKeyTy                                 // Pay pubkey.
	PubKeyHashTy                             // Pay pubkey hash.
	WitnessV0PubKeyHashTy                    // Pay witness pubkey hash.
	ScriptHashTy                             // Pay to script hash.
	WitnessV0ScriptHashTy                    // Pay to witness script hash.
	MultiSigTy                               // Multi signature.
	NullDataTy                               // Empty data-only (provably prunable).
	WitnessUnknownTy                         // Witness unknown
)

// scriptClassToName houses the human-readable strings which describe each
// script class.
var scriptClassToName = []string{
	NonStandardTy:         "nonstandard",
	PubKeyTy:              "pubkey",
	PubKeyHashTy:          "pubkeyhash",
	WitnessV0PubKeyHashTy: "witness_v0_keyhash",
	ScriptHashTy:          "scripthash",
	WitnessV0ScriptHashTy: "witness_v0_scripthash",
	MultiSigTy:            "multisig",
	NullDataTy:            "nulldata",
	WitnessUnknownTy:      "witness_unknown",
}

// String implements the Stringer interface by returning the name of
// the enum script class. If the enum is invalid then "Invalid" will be
// returned.
func (t ScriptClass) String() string {
	if int(t) > len(scriptClassToName) || int(t) < 0 {
		return "Invalid"
	}
	return scriptClassToName[t]
}

// isPubkey returns true if the script passed is a pay-to-pubkey transaction,
// false otherwise.
func isPubkey(script []byte) bool {
	if len(script) == 35 {
		if script[34] == OP_CHECKSIG {
			return true
		}
	}

	if len(script) == 67 {
		if script[66] == OP_CHECKSIG {
			return true
		}
	}

	return false
}

//// isPubkey returns true if the script passed is a pay-to-pubkey transaction,
//// false otherwise.
//func isPubkey(pops []parsedOpcode) bool {
//	// Valid pubkeys are either 33 or 65 bytes.
//	return len(pops) == 2 &&
//		(len(pops[0].data) == 33 || len(pops[0].data) == 65) &&
//		pops[1].opcode.value == OP_CHECKSIG
//}

// extractCompressedPubKey extracts a compressed public key from the passed
// script if it is a standard pay-to-compressed-secp256k1-pubkey script.  It
// will return nil otherwise.
func extractCompressedPubKey(script []byte) []byte {
	// A pay-to-compressed-pubkey script is of the form:
	//  OP_DATA_33 <33-byte compressed pubkey> OP_CHECKSIG

	// All compressed secp256k1 public keys must start with 0x02 or 0x03.
	if len(script) == 35 &&
		script[34] == OP_CHECKSIG &&
		script[0] == OP_DATA_33 &&
		(script[1] == 0x02 || script[1] == 0x03) {

		return script[1:34]
	}

	return nil
}

// extractUncompressedPubKey extracts an uncompressed public key from the
// passed script if it is a standard pay-to-uncompressed-secp256k1-pubkey
// script.  It will return nil otherwise.
func extractUncompressedPubKey(script []byte) []byte {
	// A pay-to-uncompressed-pubkey script is of the form:
	//  OP_DATA_65 <65-byte uncompressed pubkey> OP_CHECKSIG

	// All non-hybrid uncompressed secp256k1 public keys must start with 0x04.
	if len(script) == 67 &&
		script[66] == OP_CHECKSIG &&
		script[0] == OP_DATA_65 {
		//script[1] == 0x04 {

		return script[1:66]
	}

	return nil
}

// extractPubKey extracts either a compressed or uncompressed public key from the
// passed script if it is either a standard pay-to-compressed-secp256k1-pubkey
// or pay-to-uncompressed-secp256k1-pubkey script, respectively.  It will return
// nil otherwise.
func extractPubKey(script []byte) []byte {
	if pubKey := extractCompressedPubKey(script); pubKey != nil {
		return pubKey
	}
	return extractUncompressedPubKey(script)
}

// isPubkeyHash returns true if the script passed is a pay-to-pubkey-hash
// transaction, false otherwise.
func isPubkeyHash(script []byte) bool {
	return len(script) == 25 &&
		script[0] == OP_DUP &&
		script[1] == OP_HASH160 &&
		script[2] == OP_DATA_20 &&
		script[23] == OP_EQUALVERIFY &&
		script[24] == OP_CHECKSIG
}

//// isPubkeyHash returns true if the script passed is a pay-to-pubkey-hash
//// transaction, false otherwise.
//func isPubkeyHash(pops []parsedOpcode) bool {
//	return len(pops) == 5 &&
//		pops[0].opcode.value == OP_DUP &&
//		pops[1].opcode.value == OP_HASH160 &&
//		pops[2].opcode.value == OP_DATA_20 &&
//		pops[3].opcode.value == OP_EQUALVERIFY &&
//		pops[4].opcode.value == OP_CHECKSIG
//
//}

//// isMultiSig returns true if the passed script is a multisig transaction, false
//// otherwise.
//func isMultiSig(pops []parsedOpcode) bool {
//	// The absolute minimum is 1 pubkey:
//	// OP_0/OP_1-16 <pubkey> OP_1 OP_CHECKMULTISIG
//	l := len(pops)
//	if l < 4 {
//		return false
//	}
//	if !isSmallIntNew(pops[0].opcode) {
//		return false
//	}
//	if !isSmallIntNew(pops[l-2].opcode) {
//		return false
//	}
//	if pops[l-1].opcode.value != OP_CHECKMULTISIG {
//		return false
//	}
//
//	// Verify the number of pubkeys specified matches the actual number
//	// of pubkeys provided.
//	if l-2-1 != AsSmallIntNew(pops[l-2].opcode) {
//		return false
//	}
//
//	for _, pop := range pops[1 : l-2] {
//		// Valid pubkeys are either 33 or 65 bytes.
//		if len(pop.data) != 33 && len(pop.data) != 65 {
//			return false
//		}
//	}
//	return true
//}

// isMultiSig returns whether or not the passed script is a standard
// multisig script.
func isMultiSig(script []byte) bool {
	// Since this is only checking the form of the script, don't extract the
	// public keys to avoid the allocation.
	details := extractMultisigScriptDetails(script, false)
	return details.valid
}

// multiSigDetails houses details extracted from a standard multisig script.
type multiSigDetails struct {
	requiredSigs int
	numPubKeys   int
	pubKeys      [][]byte
	valid        bool
}

// extractMultisigScriptDetails attempts to extract details from the passed
// script if it is a standard multisig script.  The returned details struct will
// have the valid flag set to false otherwise.
//
// The extract pubkeys flag indicates whether or not the pubkeys themselves
// should also be extracted and is provided because extracting them results in
// an allocation that the caller might wish to avoid.  The pubKeys member of
// the returned details struct will be nil when the flag is false.
func extractMultisigScriptDetails(script []byte, extractPubKeys bool) multiSigDetails {
	// A multi-signature script is of the form:
	//  NUM_SIGS PUBKEY PUBKEY PUBKEY ... NUM_PUBKEYS OP_CHECKMULTISIG

	// The script can't possibly be a multisig script if it doesn't end with
	// OP_CHECKMULTISIG or have at least two small integer pushes preceding it.
	// Fail fast to avoid more work below.
	if len(script) < 3 || script[len(script)-1] != OP_CHECKMULTISIG {
		return multiSigDetails{}
	}

	// The first opcode must be a small integer specifying the number of
	// signatures required.
	tokenizer := MakeScriptTokenizer(script)
	if !tokenizer.Next() || !isSmallIntNew(tokenizer.Opcode()) {
		return multiSigDetails{}
	}
	requiredSigs := AsSmallIntNew(tokenizer.Opcode())

	// The next series of opcodes must either push public keys or be a small
	// integer specifying the number of public keys.
	var numPubKeys int
	var pubKeys [][]byte
	if extractPubKeys {
		pubKeys = make([][]byte, 0, MaxPubKeysPerMultiSig)
	}
	for tokenizer.Next() {
		data := tokenizer.Data()
		if !isPubKeyEncoding(data) {
			break
		}
		numPubKeys++
		if extractPubKeys {
			pubKeys = append(pubKeys, data)
		}
	}

	if tokenizer.Done() {
		return multiSigDetails{}
	}

	// The next opcode must be a small integer specifying the number of public
	// keys required.
	op := tokenizer.Opcode()
	if !isSmallIntNew(op) || AsSmallIntNew(op) != numPubKeys {
		return multiSigDetails{}
	}

	// There must only be a single opcode left unparsed which will be
	// OP_CHECKMULTISIG per the check above.
	if int32(len(tokenizer.Script()))-tokenizer.ByteIndex() != 1 {
		return multiSigDetails{}
	}

	return multiSigDetails{
		requiredSigs: requiredSigs,
		numPubKeys:   numPubKeys,
		pubKeys:      pubKeys,
		valid:        true,
	}
}

// extractPubKeyHash extracts the public key hash from the passed script if it
// is a standard pay-to-pubkey-hash script.  It will return nil otherwise.
func extractPubKeyHash(script []byte) []byte {
	// A pay-to-pubkey-hash script is of the form:
	//  OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
	if len(script) == 25 &&
		script[0] == OP_DUP &&
		script[1] == OP_HASH160 &&
		script[2] == OP_DATA_20 &&
		script[23] == OP_EQUALVERIFY &&
		script[24] == OP_CHECKSIG {

		return script[3:23]
	}

	return nil
}

// extractWitnessV0PubKeyHash extracts the public key hash from the passed script if it
// is a standard pay-to-witnessV0-pubkey-hash script.  It will return nil otherwise.
func extractWitnessV0PubKeyHash(script []byte) []byte {
	// A pay-to-witness-pubkey-hash script is of the form:
	//  OP_0 <20-byte hash>
	if len(script) == 22 &&
		script[0] == OP_0 &&
		script[1] == OP_DATA_20 {

		return script[2:21]
	}

	return nil
}

//// isNullData returns true if the passed script is a null data transaction,
//// false otherwise.
//func isNullData(pops []parsedOpcode) bool {
//	// A nulldata transaction is either a single OP_RETURN or an
//	// OP_RETURN SMALLDATA (where SMALLDATA is a data push up to
//	// MaxDataCarrierSize bytes).
//	l := len(pops)
//	if l == 1 && pops[0].opcode.value == OP_RETURN {
//		return true
//	}
//
//	return l == 2 &&
//		pops[0].opcode.value == OP_RETURN &&
//		(isSmallInt(pops[1].opcode) || pops[1].opcode.value <=
//			OP_PUSHDATA4) &&
//		len(pops[1].data) <= MaxDataCarrierSize
//}

// isNullData returns whether or not the passed script is a standard
// null data script.
func isNullData(script []byte) bool {
	// A null script is of the form:
	//  OP_RETURN <optional data>
	//
	// Thus, it can either be a single OP_RETURN or an OP_RETURN followed by a
	// data push up to MaxDataCarrierSize bytes.

	// The script can't possibly be a null data script if it doesn't start
	// with OP_RETURN.  Fail fast to avoid more work below.
	if len(script) < 1 || script[0] != OP_RETURN {
		return false
	}

	// Single OP_RETURN.
	if len(script) == 1 {
		return true
	}

	// OP_RETURN followed by data push up to MaxDataCarrierSize bytes.
	tokenizer := MakeScriptTokenizer(script[1:])
	return tokenizer.Next() && tokenizer.Done() &&
		(isSmallIntNew(tokenizer.Opcode()) || tokenizer.Opcode() <= OP_PUSHDATA4) &&
		len(tokenizer.Data()) <= MaxDataCarrierSize
}

// scriptType returns the type of the script being inspected from the known
// standard types.
func typeOfScript(script []byte) ScriptClass {
	if isPubkey(script) {
		return PubKeyTy
	} else if isPubkeyHash(script) {
		return PubKeyHashTy
	} else if isWitnessPubKeyHashNew(script) {
		return WitnessV0PubKeyHashTy
	} else if isScriptHashNew(script) {
		return ScriptHashTy
	} else if isWitnessScriptHashNew(script) {
		return WitnessV0ScriptHashTy
	} else if isMultiSig(script) {
		return MultiSigTy
	} else if isNullData(script) {
		return NullDataTy
	}
	return NonStandardTy
}

// GetScriptClass returns the class of the script passed.
//
// NonStandardTy will be returned when the script does not parse.
func GetScriptClass(script []byte) ScriptClass {
	//pops, err := parseScript(script)
	//if err != nil {
	//	return NonStandardTy
	//}
	return typeOfScript(script)
}

// NewScriptClass returns the ScriptClass corresponding to the string name
// provided as argument. ErrUnsupportedScriptType error is returned if the
// name doesn't correspond to any known ScriptClass.
//
// Not to be confused with GetScriptClass.
func NewScriptClass(name string) (*ScriptClass, error) {
	for i, n := range scriptClassToName {
		if n == name {
			value := ScriptClass(i)
			return &value, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedScriptType, name)
}

// expectedInputs returns the number of arguments required by a script.
// If the script is of unknown type such that the number can not be determined
// then -1 is returned. We are an internal function and thus assume that class
// is the real class of pops (and we can thus assume things that were determined
// while finding out the type).
func expectedInputs(script []byte, class ScriptClass) int {
	switch class {
	case PubKeyTy:
		return 1

	case PubKeyHashTy:
		return 2

	case WitnessV0PubKeyHashTy:
		return 2

	case ScriptHashTy:
		// Not including script.  That is handled by the caller.
		return 1

	case WitnessV0ScriptHashTy:
		// Not including script.  That is handled by the caller.
		return 1

	case MultiSigTy:
		// Standard multisig has a push a small number for the number
		// of sigs and number of keys.  Check the first push instruction
		// to see how many arguments are expected. typeOfScript already
		// checked this so we know it'll be a small int.  Also, due to
		// the original bitcoind bug where OP_CHECKMULTISIG pops an
		// additional item from the stack, add an extra expected input
		// for the extra push that is required to compensate.
		return AsSmallIntNew(script[0]) + 1

	case NullDataTy:
		fallthrough
	default:
		return -1
	}
}

// ScriptInfo houses information about a script pair that is determined by
// CalcScriptInfo.
type ScriptInfo struct {
	// PkScriptClass is the class of the public key script and is equivalent
	// to calling GetScriptClass on it.
	PkScriptClass ScriptClass

	// NumInputs is the number of inputs provided by the public key script.
	NumInputs int

	// ExpectedInputs is the number of outputs required by the signature
	// script and any pay-to-script-hash scripts. The number will be -1 if
	// unknown.
	ExpectedInputs int

	// SigOps is the number of signature operations in the script pair.
	SigOps int
}

// CalcScriptInfo returns a structure providing data about the provided script
// pair.  It will error if the pair is in someway invalid such that they can not
// be analysed, i.e. if they do not parse or the pkScript is not a push-only
// script
func CalcScriptInfo(sigScript, pkScript []byte, witness wire.TxWitness,
	bip16, segwit bool) (*ScriptInfo, error) {

	//sigPops, err := parseScript(sigScript)
	//if err != nil {
	//	return nil, err
	//}

	//pkPops, err := parseScript(pkScript)
	//if err != nil {
	//	return nil, err
	//}
	var numInputs int
	tokenizer := MakeScriptTokenizer(sigScript)
	for tokenizer.Next() {
		numInputs++
	}
	if err := tokenizer.Err(); err != nil {
		return nil, err
	}

	if err := checkScriptParses(pkScript); err != nil {
		return nil, err
	}

	// Can't have a signature script that doesn't just push data.
	if !IsPushOnlyScript(sigScript) {
		return nil, scriptError(ErrNotPushOnly,
			"signature script is not push only")
	}

	si := new(ScriptInfo)
	si.PkScriptClass = typeOfScript(pkScript)

	si.ExpectedInputs = expectedInputs(pkScript, si.PkScriptClass)

	// All entries pushed to stack (or are OP_RESERVED and exec will fail).
	si.NumInputs = numInputs

	//// Push only sigScript makes little sense.
	//si := new(ScriptInfo)
	//si.PkScriptClass = typeOfScript(pkScript)

	//// Can't have a signature script that doesn't just push data.
	//if !IsPushOnlyScript(sigScript) {
	//	return nil, scriptError(ErrNotPushOnly,
	//		"signature script is not push only")
	//}

	//si.ExpectedInputs = expectedInputs(pkScript, si.PkScriptClass)

	switch {
	// Count sigops taking into account pay-to-script-hash.
	case si.PkScriptClass == ScriptHashTy && bip16 && !segwit:
		// The pay-to-hash-script is the final data push of the
		// signature script.
		//script := sigPops[len(sigPops)-1].data
		script := finalOpcodeData(sigScript)
		//shPops, err := parseScript(script)
		//if err != nil {
		//	return nil, err
		//}

		shInputs := expectedInputs(script, typeOfScript(script))
		if shInputs == -1 {
			si.ExpectedInputs = -1
		} else {
			si.ExpectedInputs += shInputs
		}
		si.SigOps = countSigOps(script, true)

		// All entries pushed to stack (or are OP_RESERVED and exec
		// will fail).
		//si.NumInputs = len(sigScript)

	// If segwit is active, and this is a regular p2wkh output, then we'll
	// treat the script as a p2pkh output in essence.
	case si.PkScriptClass == WitnessV0PubKeyHashTy && segwit:

		si.SigOps = GetWitnessSigOpCount(sigScript, pkScript, witness)
		si.NumInputs = len(witness)

	// We'll attempt to detect the nested p2sh case so we can accurately
	// count the signature operations involved.
	case si.PkScriptClass == ScriptHashTy &&
		IsWitnessProgram(sigScript[1:]) && bip16 && segwit:

		// Extract the pushed witness program from the sigScript so we
		// can determine the number of expected inputs.
		//pkPops, _ := parseScript(sigScript[1:])
		shInputs := expectedInputs(sigScript[1:], typeOfScript(sigScript[1:]))
		if shInputs == -1 {
			si.ExpectedInputs = -1
		} else {
			si.ExpectedInputs += shInputs
		}

		si.SigOps = GetWitnessSigOpCount(sigScript, pkScript, witness)

		si.NumInputs += len(witness)
		//si.NumInputs += len(sigScript)

	// If segwit is active, and this is a p2wsh output, then we'll need to
	// examine the witness script to generate accurate script info.
	case si.PkScriptClass == WitnessV0ScriptHashTy && segwit:
		// The witness script is the final element of the witness
		// stack.
		witnessScript := witness[len(witness)-1]
		//pops, _ := parseScript(witnessScript)

		shInputs := expectedInputs(witnessScript, typeOfScript(witnessScript))
		if shInputs == -1 {
			si.ExpectedInputs = -1
		} else {
			si.ExpectedInputs += shInputs
		}

		si.SigOps = GetWitnessSigOpCount(sigScript, pkScript, witness)
		si.NumInputs = len(witness)

	default:
		si.SigOps = countSigOps(pkScript, true)

		// All entries pushed to stack (or are OP_RESERVED and exec
		// will fail).
		//si.NumInputs = len(sigScript)
	}

	return si, nil
}

//// CalcScriptInfo returns a structure providing data about the provided script
//// pair.  It will error if the pair is in someway invalid such that they can not
//// be analysed, i.e. if they do not parse or the pkScript is not a push-only
//// script
//func CalcScriptInfo(sigScript, pkScript []byte, bip16 bool) (*ScriptInfo, error) {
//	// Count the number of opcodes in the signature script while also ensuring
//	// that successfully parses.  Since there is a check below to ensure the
//	// script is push only, this equates to the number of inputs to the public
//	// key script.
//	const scriptVersion = 0
//	var numInputs int
//	tokenizer := MakeScriptTokenizer(sigScript)
//	for tokenizer.Next() {
//		numInputs++
//	}
//	if err := tokenizer.Err(); err != nil {
//		return nil, err
//	}
//
//	if err := checkScriptParses(pkScript); err != nil {
//		return nil, err
//	}
//
//	// Can't have a signature script that doesn't just push data.
//	if !IsPushOnlyScript(sigScript) {
//		return nil, scriptError(ErrNotPushOnly,
//			"signature script is not push only")
//	}
//
//	si := new(ScriptInfo)
//	si.PkScriptClass = typeOfScript(pkScript)
//
//	si.ExpectedInputs = expectedInputs(pkScript, si.PkScriptClass)
//
//	// All entries pushed to stack (or are OP_RESERVED and exec will fail).
//	si.NumInputs = numInputs
//
//	// Count sigops taking into account pay-to-script-hash.
//	if (si.PkScriptClass == ScriptHashTy) && bip16 {
//		// The redeem script is the final data push of the signature script.
//		redeemScript := finalOpcodeData(sigScript)
//		reedeemClass := typeOfScript(redeemScript)
//		rsInputs := expectedInputs(redeemScript, reedeemClass)
//		if rsInputs == -1 {
//			si.ExpectedInputs = -1
//		} else {
//			si.ExpectedInputs += rsInputs
//		}
//		si.SigOps = countSigOps(redeemScript, true)
//	} else {
//		si.SigOps = countSigOps(pkScript, true)
//	}
//
//	return si, nil
//}

// CalcMultiSigStats returns the number of public keys and signatures from
// a multi-signature transaction script.  The passed script MUST already be
// known to be a multi-signature script.
func CalcMultiSigStats(script []byte) (int, int, error) {
	//pops, err := parseScript(script)
	//if err != nil {
	//	return 0, 0, err
	//}

	//// A multi-signature script is of the pattern:
	////  NUM_SIGS PUBKEY PUBKEY PUBKEY... NUM_PUBKEYS OP_CHECKMULTISIG
	//// Therefore the number of signatures is the oldest item on the stack
	//// and the number of pubkeys is the 2nd to last.  Also, the absolute
	//// minimum for a multi-signature script is 1 pubkey, so at least 4
	//// items must be on the stack per:
	////  OP_1 PUBKEY OP_1 OP_CHECKMULTISIG
	//if len(pops) < 4 {
	//	str := fmt.Sprintf("script %x is not a multisig script", script)
	//	return 0, 0, scriptError(ErrNotMultisigScript, str)
	//}

	//numSigs := asSmallInt(pops[0].opcode)
	//numPubKeys := asSmallInt(pops[len(pops)-2].opcode)
	//return numPubKeys, numSigs, nil

	details := extractMultisigScriptDetails(script, false)
	if !details.valid {
		str := fmt.Sprintf("script %x is not a multisig script", script)
		return 0, 0, scriptError(ErrNotMultisigScript, str)
	}

	return details.numPubKeys, details.requiredSigs, nil
}

// payToPubKeyHashScript creates a new script to pay a transaction
// output to a 20-byte pubkey hash. It is expected that the input is a valid
// hash.
func payToPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(OP_DUP).AddOp(OP_HASH160).
		AddData(pubKeyHash).AddOp(OP_EQUALVERIFY).AddOp(OP_CHECKSIG).
		Script()
}

// payToWitnessPubKeyHashScript creates a new script to pay to a version 0
// pubkey hash witness program. The passed hash is expected to be valid.
func payToWitnessPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(OP_0).AddData(pubKeyHash).Script()
}

// payToScriptHashScript creates a new script to pay a transaction output to a
// script hash. It is expected that the input is a valid hash.
func payToScriptHashScript(scriptHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(OP_HASH160).AddData(scriptHash).
		AddOp(OP_EQUAL).Script()
}

// payToWitnessPubKeyHashScript creates a new script to pay to a version 0
// script hash witness program. The passed hash is expected to be valid.
func payToWitnessScriptHashScript(scriptHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(OP_0).AddData(scriptHash).Script()
}

// payToPubkeyScript creates a new script to pay a transaction output to a
// public key. It is expected that the input is a valid pubkey.
func payToPubKeyScript(serializedPubKey []byte) ([]byte, error) {
	return NewScriptBuilder().AddData(serializedPubKey).
		AddOp(OP_CHECKSIG).Script()
}

// PayToAddrScript creates a new script to pay a transaction output to a the
// specified address.
func PayToAddrScript(addr btcutil.Address) ([]byte, error) {
	const nilAddrErrStr = "unable to generate payment script for nil address"

	switch addr := addr.(type) {
	case *btcutil.AddressPubKeyHash:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToPubKeyHashScript(addr.ScriptAddress())

	case *btcutil.AddressScriptHash:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToScriptHashScript(addr.ScriptAddress())

	case *btcutil.AddressPubKey:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToPubKeyScript(addr.ScriptAddress())

	case *btcutil.AddressWitnessPubKeyHash:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToWitnessPubKeyHashScript(addr.ScriptAddress())
	case *btcutil.AddressWitnessScriptHash:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToWitnessScriptHashScript(addr.ScriptAddress())
	}

	str := fmt.Sprintf("unable to generate payment script for unsupported "+
		"address type %T", addr)
	return nil, scriptError(ErrUnsupportedAddress, str)
}

// NullDataScript creates a provably-prunable script containing OP_RETURN
// followed by the passed data.  An Error with the error code ErrTooMuchNullData
// will be returned if the length of the passed data exceeds MaxDataCarrierSize.
func NullDataScript(data []byte) ([]byte, error) {
	if len(data) > MaxDataCarrierSize {
		str := fmt.Sprintf("data size %d is larger than max "+
			"allowed size %d", len(data), MaxDataCarrierSize)
		return nil, scriptError(ErrTooMuchNullData, str)
	}

	return NewScriptBuilder().AddOp(OP_RETURN).AddData(data).Script()
}

// MultiSigScript returns a valid script for a multisignature redemption where
// nrequired of the keys in pubkeys are required to have signed the transaction
// for success.  An Error with the error code ErrTooManyRequiredSigs will be
// returned if nrequired is larger than the number of keys provided.
func MultiSigScript(pubkeys []*btcutil.AddressPubKey, nrequired int) ([]byte, error) {
	if len(pubkeys) < nrequired {
		str := fmt.Sprintf("unable to generate multisig script with "+
			"%d required signatures when there are only %d public "+
			"keys available", nrequired, len(pubkeys))
		return nil, scriptError(ErrTooManyRequiredSigs, str)
	}

	builder := NewScriptBuilder().AddInt64(int64(nrequired))
	for _, key := range pubkeys {
		builder.AddData(key.ScriptAddress())
	}
	builder.AddInt64(int64(len(pubkeys)))
	builder.AddOp(OP_CHECKMULTISIG)

	return builder.Script()
}

// PushedData returns an array of byte slices containing any pushed data found
// in the passed script.  This includes OP_0, but not OP_1 - OP_16.
func PushedData(script []byte) ([][]byte, error) {
	//pops, err := parseScript(script)
	//if err != nil {
	//	return nil, err
	//}

	//var data [][]byte
	//for _, pop := range pops {
	//	if pop.data != nil {
	//		data = append(data, pop.data)
	//	} else if pop.opcode.value == OP_0 {
	//		data = append(data, nil)
	//	}
	//}
	//return data, nil

	var data [][]byte
	tokenizer := MakeScriptTokenizer(script)
	for tokenizer.Next() {
		if tokenizer.Data() != nil {
			data = append(data, tokenizer.Data())
		} else if tokenizer.Opcode() == OP_0 {
			data = append(data, nil)
		}
	}
	if err := tokenizer.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

//// ExtractPkScriptAddrs returns the type of script, addresses and required
//// signatures associated with the passed PkScript.  Note that it only works for
//// 'standard' transaction script types.  Any data such as public keys which are
//// invalid are omitted from the results.
//func ExtractPkScriptAddrs(pkScript []byte, chainParams *chaincfg.Params) (ScriptClass, []btcutil.Address, int, error) {
//	var addrs []btcutil.Address
//	var requiredSigs int
//
//	// No valid addresses or required signatures if the script doesn't
//	// parse.
//	pops, err := parseScript(pkScript)
//	if err != nil {
//		return NonStandardTy, nil, 0, err
//	}
//
//	scriptClass := typeOfScript(pops)
//	switch scriptClass {
//	case PubKeyHashTy:
//		// A pay-to-pubkey-hash script is of the form:
//		//  OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
//		// Therefore the pubkey hash is the 3rd item on the stack.
//		// Skip the pubkey hash if it's invalid for some reason.
//		requiredSigs = 1
//		addr, err := btcutil.NewAddressPubKeyHash(pops[2].data,
//			chainParams)
//		if err == nil {
//			addrs = append(addrs, addr)
//		}
//
//	case WitnessV0PubKeyHashTy:
//		// A pay-to-witness-pubkey-hash script is of thw form:
//		//  OP_0 <20-byte hash>
//		// Therefore, the pubkey hash is the second item on the stack.
//		// Skip the pubkey hash if it's invalid for some reason.
//		requiredSigs = 1
//		addr, err := btcutil.NewAddressWitnessPubKeyHash(pops[1].data,
//			chainParams)
//		if err == nil {
//			addrs = append(addrs, addr)
//		}
//
//	case PubKeyTy:
//		// A pay-to-pubkey script is of the form:
//		//  <pubkey> OP_CHECKSIG
//		// Therefore the pubkey is the first item on the stack.
//		// Skip the pubkey if it's invalid for some reason.
//		requiredSigs = 1
//		addr, err := btcutil.NewAddressPubKey(pops[0].data, chainParams)
//		if err == nil {
//			addrs = append(addrs, addr)
//		}
//
//	case ScriptHashTy:
//		// A pay-to-script-hash script is of the form:
//		//  OP_HASH160 <scripthash> OP_EQUAL
//		// Therefore the script hash is the 2nd item on the stack.
//		// Skip the script hash if it's invalid for some reason.
//		requiredSigs = 1
//		addr, err := btcutil.NewAddressScriptHashFromHash(pops[1].data,
//			chainParams)
//		if err == nil {
//			addrs = append(addrs, addr)
//		}
//
//	case WitnessV0ScriptHashTy:
//		// A pay-to-witness-script-hash script is of the form:
//		//  OP_0 <32-byte hash>
//		// Therefore, the script hash is the second item on the stack.
//		// Skip the script hash if it's invalid for some reason.
//		requiredSigs = 1
//		addr, err := btcutil.NewAddressWitnessScriptHash(pops[1].data,
//			chainParams)
//		if err == nil {
//			addrs = append(addrs, addr)
//		}
//
//	case MultiSigTy:
//		// A multi-signature script is of the form:
//		//  <numsigs> <pubkey> <pubkey> <pubkey>... <numpubkeys> OP_CHECKMULTISIG
//		// Therefore the number of required signatures is the 1st item
//		// on the stack and the number of public keys is the 2nd to last
//		// item on the stack.
//		requiredSigs = asSmallInt(pops[0].opcode)
//		numPubKeys := asSmallInt(pops[len(pops)-2].opcode)
//
//		// Extract the public keys while skipping any that are invalid.
//		addrs = make([]btcutil.Address, 0, numPubKeys)
//		for i := 0; i < numPubKeys; i++ {
//			addr, err := btcutil.NewAddressPubKey(pops[i+1].data,
//				chainParams)
//			if err == nil {
//				addrs = append(addrs, addr)
//			}
//		}
//
//	case NullDataTy:
//		// Null data transactions have no addresses or required
//		// signatures.
//
//	case NonStandardTy:
//		// Don't attempt to extract addresses or required signatures for
//		// nonstandard transactions.
//	}
//
//	return scriptClass, addrs, requiredSigs, nil
//}

// pubKeyHashToAddrs is a convenience function to attempt to convert the
// passed hash to a pay-to-pubkey-hash address housed within an address
// slice.  It is used to consolidate common code.
func pubKeyHashToAddrs(hash []byte, chainParams *chaincfg.Params) []btcutil.Address {
	// Skip the pubkey hash if it's invalid for some reason.
	var addrs []btcutil.Address
	addr, err := btcutil.NewAddressPubKeyHash(hash, chainParams)
	if err == nil {
		addrs = append(addrs, addr)
	}
	return addrs
}

// scriptHashToAddrs is a convenience function to attempt to convert the passed
// hash to a pay-to-script-hash address housed within an address slice.  It is
// used to consolidate common code.
func scriptHashToAddrs(hash []byte, chainParams *chaincfg.Params) []btcutil.Address {
	// Skip the hash if it's invalid for some reason.
	var addrs []btcutil.Address
	addr, err := btcutil.NewAddressScriptHashFromHash(hash, chainParams)
	if err == nil {
		addrs = append(addrs, addr)
	}
	return addrs
}

// ExtractPkScriptAddrs returns the type of script, addresses and required
// signatures associated with the passed PkScript.  Note that it only works for
// 'standard' transaction script types.  Any data such as public keys which are
// invalid are omitted from the results.
func ExtractPkScriptAddrs(pkScript []byte, chainParams *chaincfg.Params) (ScriptClass, []btcutil.Address, int, error) {
	var addrs []btcutil.Address
	var requiredSigs int

	scriptClass := typeOfScript(pkScript)
	switch scriptClass {
	case PubKeyHashTy:
		// A pay-to-pubkey-hash script is of the form:
		//  OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
		// Therefore the pubkey hash is the 3rd item on the stack.
		// Skip the pubkey hash if it's invalid for some reason.
		requiredSigs = 1
		data := extractPubKeyHash(pkScript)
		addr, err := btcutil.NewAddressPubKeyHash(data,
			chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case WitnessV0PubKeyHashTy:
		// A pay-to-witness-pubkey-hash script is of thw form:
		//  OP_0 <20-byte hash>
		// Therefore, the pubkey hash is the second item on the stack.
		// Skip the pubkey hash if it's invalid for some reason.
		requiredSigs = 1
		data := extractWitnessV0PubKeyHash(pkScript)
		addr, err := btcutil.NewAddressWitnessPubKeyHash(data,
			chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case PubKeyTy:
		// A pay-to-pubkey script is of the form:
		//  <pubkey> OP_CHECKSIG
		// Therefore the pubkey is the first item on the stack.
		// Skip the pubkey if it's invalid for some reason.
		requiredSigs = 1
		data := extractPubKey(pkScript)
		addr, err := btcutil.NewAddressPubKey(data, chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case ScriptHashTy:
		// A pay-to-script-hash script is of the form:
		//  OP_HASH160 <scripthash> OP_EQUAL
		// Therefore the script hash is the 2nd item on the stack.
		// Skip the script hash if it's invalid for some reason.
		requiredSigs = 1
		data := ExtractScriptHash(pkScript)
		addr, err := btcutil.NewAddressScriptHashFromHash(data,
			chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case WitnessV0ScriptHashTy:
		// A pay-to-witness-script-hash script is of the form:
		//  OP_0 <32-byte hash>
		// Therefore, the script hash is the second item on the stack.
		// Skip the script hash if it's invalid for some reason.
		requiredSigs = 1
		data := ExtractWitnessV0ScriptHash(pkScript)
		addr, err := btcutil.NewAddressWitnessScriptHash(data,
			chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case MultiSigTy:
		// A multi-signature script is of the form:
		//  <numsigs> <pubkey> <pubkey> <pubkey>... <numpubkeys> OP_CHECKMULTISIG
		// Therefore the number of required signatures is the 1st item
		// on the stack and the number of public keys is the 2nd to last
		// item on the stack.
		details := extractMultisigScriptDetails(pkScript, true)
		requiredSigs = details.requiredSigs

		// Extract the public keys while skipping any that are invalid.
		//addrsBuf := make([]btcutil.Address, 0, details.numPubKeys)
		for i := 0; i < details.numPubKeys; i++ {
			addr, err := btcutil.NewAddressPubKey(details.pubKeys[i], chainParams)
			if err == nil {
				addrs = append(addrs, addr)
			}
		}

	case NullDataTy:
		// Null data transactions have no addresses or required
		// signatures.

	case NonStandardTy:
		// Don't attempt to extract addresses or required signatures for
		// nonstandard transactions.
	}

	return scriptClass, addrs, requiredSigs, nil
}

// AtomicSwapDataPushes houses the data pushes found in atomic swap contracts.
type AtomicSwapDataPushes struct {
	RecipientHash160 [20]byte
	RefundHash160    [20]byte
	SecretHash       [32]byte
	SecretSize       int64
	LockTime         int64
}

//// ExtractAtomicSwapDataPushes returns the data pushes from an atomic swap
//// contract.  If the script is not an atomic swap contract,
//// ExtractAtomicSwapDataPushes returns (nil, nil).  Non-nil errors are returned
//// for unparsable scripts.
////
//// NOTE: Atomic swaps are not considered standard script types by the dcrd
//// mempool policy and should be used with P2SH.  The atomic swap format is also
//// expected to change to use a more secure hash function in the future.
////
//// This function is only defined in the txscript package due to API limitations
//// which prevent callers using txscript to parse nonstandard scripts.
//func ExtractAtomicSwapDataPushes(version uint16, pkScript []byte) (*AtomicSwapDataPushes, error) {
//	pops, err := parseScript(pkScript)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(pops) != 20 {
//		return nil, nil
//	}
//	isAtomicSwap := pops[0].opcode.value == OP_IF &&
//		pops[1].opcode.value == OP_SIZE &&
//		canonicalPush(pops[2]) &&
//		pops[3].opcode.value == OP_EQUALVERIFY &&
//		pops[4].opcode.value == OP_SHA256 &&
//		pops[5].opcode.value == OP_DATA_32 &&
//		pops[6].opcode.value == OP_EQUALVERIFY &&
//		pops[7].opcode.value == OP_DUP &&
//		pops[8].opcode.value == OP_HASH160 &&
//		pops[9].opcode.value == OP_DATA_20 &&
//		pops[10].opcode.value == OP_ELSE &&
//		canonicalPush(pops[11]) &&
//		pops[12].opcode.value == OP_CHECKLOCKTIMEVERIFY &&
//		pops[13].opcode.value == OP_DROP &&
//		pops[14].opcode.value == OP_DUP &&
//		pops[15].opcode.value == OP_HASH160 &&
//		pops[16].opcode.value == OP_DATA_20 &&
//		pops[17].opcode.value == OP_ENDIF &&
//		pops[18].opcode.value == OP_EQUALVERIFY &&
//		pops[19].opcode.value == OP_CHECKSIG
//	if !isAtomicSwap {
//		return nil, nil
//	}
//
//	pushes := new(AtomicSwapDataPushes)
//	copy(pushes.SecretHash[:], pops[5].data)
//	copy(pushes.RecipientHash160[:], pops[9].data)
//	copy(pushes.RefundHash160[:], pops[16].data)
//	if pops[2].data != nil {
//		locktime, err := makeScriptNum(pops[2].data, true, 5)
//		if err != nil {
//			return nil, nil
//		}
//		pushes.SecretSize = int64(locktime)
//	} else if op := pops[2].opcode; isSmallIntNew(op) {
//		pushes.SecretSize = int64(asSmallInt(op))
//	} else {
//		return nil, nil
//	}
//	if pops[11].data != nil {
//		locktime, err := makeScriptNum(pops[11].data, true, 5)
//		if err != nil {
//			return nil, nil
//		}
//		pushes.LockTime = int64(locktime)
//	} else if op := pops[11].opcode; isSmallIntNew(op) {
//		pushes.LockTime = int64(asSmallInt(op))
//	} else {
//		return nil, nil
//	}
//	return pushes, nil
//}

// ExtractAtomicSwapDataPushes returns the data pushes from an atomic swap
// contract.  If the script is not an atomic swap contract,
// ExtractAtomicSwapDataPushes returns (nil, nil).  Non-nil errors are returned
// for unparsable scripts.
//
// NOTE: Atomic swaps are not considered standard script types by the dcrd
// mempool policy and should be used with P2SH.  The atomic swap format is also
// expected to change to use a more secure hash function in the future.
//
// This function is only defined in the txscript package due to API limitations
// which prevent callers using txscript to parse nonstandard scripts.
func ExtractAtomicSwapDataPushes(version uint16, pkScript []byte) (*AtomicSwapDataPushes, error) {
	// An atomic swap is of the form:
	//  IF
	//   SIZE <secret size> EQUALVERIFY SHA256 <32-byte secret> EQUALVERIFY DUP
	//   HASH160 <20-byte recipient hash>
	//  ELSE
	//   <locktime> CHECKLOCKTIMEVERIFY DROP DUP HASH160 <20-byte refund hash>
	//  ENDIF
	//  EQUALVERIFY CHECKSIG
	type templateMatch struct {
		expectCanonicalInt bool
		maxIntBytes        int
		opcode             byte
		extractedInt       int64
		extractedData      []byte
	}
	var template = [20]templateMatch{
		{opcode: OP_IF},
		{opcode: OP_SIZE},
		{expectCanonicalInt: true, maxIntBytes: MathOpCodeMaxScriptNumLen},
		{opcode: OP_EQUALVERIFY},
		{opcode: OP_SHA256},
		{opcode: OP_DATA_32},
		{opcode: OP_EQUALVERIFY},
		{opcode: OP_DUP},
		{opcode: OP_HASH160},
		{opcode: OP_DATA_20},
		{opcode: OP_ELSE},
		{expectCanonicalInt: true, maxIntBytes: CltvMaxScriptNumLen},
		{opcode: OP_CHECKLOCKTIMEVERIFY},
		{opcode: OP_DROP},
		{opcode: OP_DUP},
		{opcode: OP_HASH160},
		{opcode: OP_DATA_20},
		{opcode: OP_ENDIF},
		{opcode: OP_EQUALVERIFY},
		{opcode: OP_CHECKSIG},
	}

	var templateOffset int
	tokenizer := MakeScriptTokenizer(pkScript)
	for tokenizer.Next() {
		// Not an atomic swap script if it has more opcodes than expected in the
		// template.
		if templateOffset >= len(template) {
			return nil, nil
		}

		op := tokenizer.Opcode()
		data := tokenizer.Data()
		tplEntry := &template[templateOffset]
		if tplEntry.expectCanonicalInt {
			switch {
			case data != nil:
				val, err := makeScriptNum(data, true, tplEntry.maxIntBytes)
				if err != nil {
					return nil, err
				}
				tplEntry.extractedInt = int64(val)

			case isSmallIntNew(op):
				tplEntry.extractedInt = int64(AsSmallIntNew(op))

			// Not an atomic swap script if the opcode does not push an int.
			default:
				return nil, nil
			}
		} else {
			if op != tplEntry.opcode {
				return nil, nil
			}

			tplEntry.extractedData = data
		}

		templateOffset++
	}
	if err := tokenizer.Err(); err != nil {
		return nil, err
	}
	if !tokenizer.Done() || templateOffset != len(template) {
		return nil, nil
	}

	// At this point, the script appears to be an atomic swap, so populate and
	// return the extracted data.
	pushes := AtomicSwapDataPushes{
		SecretSize: template[2].extractedInt,
		LockTime:   template[11].extractedInt,
	}
	copy(pushes.SecretHash[:], template[5].extractedData)
	copy(pushes.RecipientHash160[:], template[9].extractedData)
	copy(pushes.RefundHash160[:], template[16].extractedData)
	return &pushes, nil
}
