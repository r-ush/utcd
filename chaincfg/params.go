// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// mainPowLimit is the highest proof of work value a Bitcoin block can
	// have for the main network.  It is the value 2^224 - 1.
	mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	// regressionPowLimit is the highest proof of work value a Bitcoin block
	// can have for the regression test network.  It is the value 2^255 - 1.
	regressionPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// testNet3PowLimit is the highest proof of work value a Bitcoin block
	// can have for the test network (version 3).  It is the value
	// 2^224 - 1.
	testNet3PowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	// simNetPowLimit is the highest proof of work value a Bitcoin block
	// can have for the simulation test network.  It is the value 2^255 - 1.
	simNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)
)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for blockchain.IsCheckpointCandidate for details on the
// selection criteria.
type Checkpoint struct {
	Height int32
	Hash   *chainhash.Hash
}

// UtreexoRootHint is a "hint" for verifying the blocks from the block that this
// root hint represents. The binary is able to assume the validity of the block
// at the root hint. This allows for a parallel blockchain initial block download
// as there is no longer the requirement to sync from genesis to tip.
type UtreexoRootHint struct {
	// Height is the block height
	Height int32
	// Hash is the Block Hash
	Hash *chainhash.Hash
	// NumLeaves is the number of utreexo tree leaves
	// aka the number of all utxos in existance for this block
	NumLeaves uint64
	// Roots are all the utreexo roots that's in existance for this block
	Roots []*chainhash.Hash
}

// FindPreviousUtreexoRootHint returns the previous Utreexo root hint
func FindPreviousUtreexoRootHint(height int32, roots []UtreexoRootHint) *UtreexoRootHint {
	if len(roots) == 0 {
		return nil
	}

	// There is no previous root if the height is already after the first
	// root.
	firstRoot := &roots[0]
	if height <= firstRoot.Height {
		return nil
	}

	// Find the previous root.
	previousRoot := firstRoot
	for i := 1; i < len(roots); i++ {
		if height <= roots[i].Height {
			break
		}
		previousRoot = &roots[i]
	}

	return previousRoot
}

// FindNextUtreexoRootHint returns the next Utreexo root hint
func FindNextUtreexoRootHint(height int32, roots []UtreexoRootHint) *UtreexoRootHint {
	if len(roots) == 0 {
		return nil
	}

	// There is no next root if the height is already after the final
	// root.
	finalRoot := &roots[len(roots)-1]
	if height >= finalRoot.Height {
		return nil
	}

	// Find the next root.
	nextRoot := finalRoot
	for i := len(roots) - 2; i >= 0; i-- {
		if height >= roots[i].Height {
			break
		}
		nextRoot = &roots[i]
	}
	return nextRoot
}

func newLeafHashFromStr(src string) *chainhash.Hash {
	// Hex decoder expects the hash to be a multiple of two.  When not, pad
	// with a leading zero.
	var srcBytes []byte
	if len(src)%2 == 0 {
		srcBytes = []byte(src)
	} else {
		srcBytes = make([]byte, 1+len(src))
		srcBytes[0] = '0'
		copy(srcBytes[1:], src)
	}

	// Hex decode the source bytes to a temporary destination.
	var reversedHash [32]byte
	_, err := hex.Decode(reversedHash[32-hex.DecodedLen(len(srcBytes)):], srcBytes)
	if err != nil {
		panic(err)
	}

	hash := chainhash.Hash(reversedHash)
	return &hash
}

// UtreexoRootHintToReader takes in a UtreexoRootHint and returns a io.Reader
// made from that RootHint
func UtreexoRootHintToReader(hint UtreexoRootHint) (io.Reader, error) {
	size := 8 + len(hint.Roots) // 8 for uint64 numLeaves
	serialized := make([]byte, 0, size)

	buf := bytes.NewBuffer(serialized)
	err := binary.Write(buf, binary.BigEndian, hint.NumLeaves)
	if err != nil {
		return nil, err
	}

	for _, t := range hint.Roots {
		_, err = buf.Write(t[:])
		if err != nil {
			return nil, err
		}
	}

	reader := bytes.NewReader(buf.Bytes())

	return reader, nil
}

// UtreexoRootHintToBytes takes in a UtreexoRootHint and returns a byte slice
func UtreexoRootHintToBytes(hint UtreexoRootHint) ([]byte, error) {
	size := 8 + len(hint.Roots) // 8 for uint64 numLeaves
	serialized := make([]byte, 0, size)

	buf := bytes.NewBuffer(serialized)
	err := binary.Write(buf, binary.BigEndian, hint.NumLeaves)
	if err != nil {
		return nil, err
	}

	for _, t := range hint.Roots {
		_, err = buf.Write(t[:])
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// DNSSeed identifies a DNS seed.
type DNSSeed struct {
	// Host defines the hostname of the seed.
	Host string

	// HasFiltering defines whether the seed supports filtering
	// by service flags (wire.ServiceFlag).
	HasFiltering bool
}

// ConsensusDeployment defines details related to a specific consensus rule
// change that is voted in.  This is part of BIP0009.
type ConsensusDeployment struct {
	// BitNumber defines the specific bit number within the block version
	// this particular soft-fork deployment refers to.
	BitNumber uint8

	// StartTime is the median block time after which voting on the
	// deployment starts.
	StartTime uint64

	// ExpireTime is the median block time after which the attempted
	// deployment expires.
	ExpireTime uint64
}

// Constants that define the deployment offset in the deployments field of the
// parameters for each deployment.  This is useful to be able to get the details
// of a specific deployment by name.
const (
	// DeploymentTestDummy defines the rule change deployment ID for testing
	// purposes.
	DeploymentTestDummy = iota

	// DeploymentCSV defines the rule change deployment ID for the CSV
	// soft-fork package. The CSV package includes the deployment of BIPS
	// 68, 112, and 113.
	DeploymentCSV

	// DeploymentSegwit defines the rule change deployment ID for the
	// Segregated Witness (segwit) soft-fork package. The segwit package
	// includes the deployment of BIPS 141, 142, 144, 145, 147 and 173.
	DeploymentSegwit

	// NOTE: DefinedDeployments must always come last since it is used to
	// determine how many defined deployments there currently are.

	// DefinedDeployments is the number of currently defined deployments.
	DefinedDeployments
)

// Params defines a Bitcoin network by its parameters.  These parameters may be
// used by Bitcoin applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	Net wire.BitcoinNet

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	DNSSeeds []DNSSeed

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash

	// PowLimit defines the highest allowed proof of work value for a block
	// as a uint256.
	PowLimit *big.Int

	// PowLimitBits defines the highest allowed proof of work value for a
	// block in compact form.
	PowLimitBits uint32

	// These fields define the block heights at which the specified softfork
	// BIP became active.
	BIP0034Height int32
	BIP0065Height int32
	BIP0066Height int32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// SubsidyReductionInterval is the interval of blocks before the subsidy
	// is reduced.
	SubsidyReductionInterval int32

	// TargetTimespan is the desired amount of time that should elapse
	// before the block difficulty requirement is examined to determine how
	// it should be changed in order to maintain the desired block
	// generation rate.
	TargetTimespan time.Duration

	// TargetTimePerBlock is the desired amount of time to generate each
	// block.
	TargetTimePerBlock time.Duration

	// RetargetAdjustmentFactor is the adjustment factor used to limit
	// the minimum and maximum amount of adjustment that can occur between
	// difficulty retargets.
	RetargetAdjustmentFactor int64

	// ReduceMinDifficulty defines whether the network should reduce the
	// minimum required difficulty after a long enough period of time has
	// passed without finding a block.  This is really only useful for test
	// networks and should not be set on a main network.
	ReduceMinDifficulty bool

	// MinDiffReductionTime is the amount of time after which the minimum
	// required difficulty should be reduced when a block hasn't been found.
	//
	// NOTE: This only applies if ReduceMinDifficulty is true.
	MinDiffReductionTime time.Duration

	// GenerateSupported specifies whether or not CPU mining is allowed.
	GenerateSupported bool

	// AssumeValid specifies all blocks before this will not have the signatures
	// checked
	AssumeValid *chainhash.Hash

	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// UtreexoRootHints ordered from oldest to newest
	UtreexoRootHints []UtreexoRootHint

	// These fields are related to voting on consensus rule changes as
	// defined by BIP0009.
	//
	// RuleChangeActivationThreshold is the number of blocks in a threshold
	// state retarget window for which a positive vote for a rule change
	// must be cast in order to lock in a rule change. It should typically
	// be 95% for the main network and 75% for test networks.
	//
	// MinerConfirmationWindow is the number of blocks in each threshold
	// state retarget window.
	//
	// Deployments define the specific consensus rule changes to be voted
	// on.
	RuleChangeActivationThreshold uint32
	MinerConfirmationWindow       uint32
	Deployments                   [DefinedDeployments]ConsensusDeployment

	// Mempool parameters
	RelayNonStdTxs bool

	// Human-readable part for Bech32 encoded segwit addresses, as defined
	// in BIP 173.
	Bech32HRPSegwit string

	// Address encoding magics
	PubKeyHashAddrID        byte // First byte of a P2PKH address
	ScriptHashAddrID        byte // First byte of a P2SH address
	PrivateKeyID            byte // First byte of a WIF private key
	WitnessPubKeyHashAddrID byte // First byte of a P2WPKH address
	WitnessScriptHashAddrID byte // First byte of a P2WSH address

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32
}

// MainNetParams defines the network parameters for the main Bitcoin network.
var MainNetParams = Params{
	Name:        "mainnet",
	Net:         wire.MainNet,
	DefaultPort: "8333",
	DNSSeeds: []DNSSeed{
		{"seed.bitcoin.sipa.be", true},
		{"dnsseed.bluematt.me", true},
		{"dnsseed.bitcoin.dashjr.org", false},
		{"seed.bitcoinstats.com", true},
		{"seed.bitnodes.io", false},
		{"seed.bitcoin.jonasschnelli.ch", true},
	},

	// Chain parameters
	GenesisBlock:             &genesisBlock,
	GenesisHash:              &genesisHash,
	PowLimit:                 mainPowLimit,
	PowLimitBits:             0x1d00ffff,
	BIP0034Height:            227931, // 000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8
	BIP0065Height:            388381, // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
	BIP0066Height:            363725, // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        false,

	AssumeValid: newHashFromStr("0000000000000000000b9d2ec5a352ecba0592946514a92f14319dc2b367fc72"), // 654683

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{11111, newHashFromStr("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
		{33333, newHashFromStr("000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
		{74000, newHashFromStr("0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
		{105000, newHashFromStr("00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
		{134444, newHashFromStr("00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
		{168000, newHashFromStr("000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
		{193000, newHashFromStr("000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
		{210000, newHashFromStr("000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
		{216116, newHashFromStr("00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e")},
		{225430, newHashFromStr("00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932")},
		{250000, newHashFromStr("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
		// NOTE The commented out bits are to match bitcoind
		//{267300, newHashFromStr("000000000000000a83fbd660e918f218bf37edd92b748ad940483c7c116179ac")},
		{295000, newHashFromStr("00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")},
		//{279000, newHashFromStr("0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40")},
		//{300255, newHashFromStr("0000000000000000162804527c6e9b9f0563a280525f9d08c12041def0a0f3b2")},
		//{319400, newHashFromStr("000000000000000021c6052e9becade189495d1c539aa37c58917305fd15f13b")},
		//{343185, newHashFromStr("0000000000000000072b8bf361d01a6ba7d445dd024203fafc78768ed4368554")},
		//{352940, newHashFromStr("000000000000000010755df42dba556bb72be6a32f3ce0b6941ce4430152c9ff")},
		//{382320, newHashFromStr("00000000000000000a8dc6ed5b133d0eb2fd6af56203e4159789b092defd8ab2")},
		//{400000, newHashFromStr("000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f")},
		//{430000, newHashFromStr("000000000000000001868b2bb3a285f3cc6b33ea234eb70facf4dcdf22186b87")},
		//{460000, newHashFromStr("000000000000000000ef751bbce8e744ad303c47ece06c8d863e4d417efc258c")},
		//{490000, newHashFromStr("000000000000000000de069137b17b8d5a3dfbd5b145b2dcfb203f15d0c4de90")},
		//{520000, newHashFromStr("0000000000000000000d26984c0229c9f6962dc74db0a6d525f2f1640396f69c")},
		//{550000, newHashFromStr("000000000000000000223b7a2298fb1c6c75fb0efc28a4c56853ff4112ec6bc9")},
		//{560000, newHashFromStr("0000000000000000002c7b276daf6efb2b6aa68e2ce3be67ef925b3264ae7122")},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1916, // 95% of MinerConfirmationWindow
	MinerConfirmationWindow:       2016, //
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  1199145601, // January 1, 2008 UTC
			ExpireTime: 1230767999, // December 31, 2008 UTC
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  1462060800, // May 1st, 2016
			ExpireTime: 1493596800, // May 1st, 2017
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  1479168000, // November 15, 2016 UTC
			ExpireTime: 1510704000, // November 15, 2017 UTC.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: false,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "bc", // always bc for main net

	// Address encoding magics
	PubKeyHashAddrID:        0x00, // starts with 1
	ScriptHashAddrID:        0x05, // starts with 3
	PrivateKeyID:            0x80, // starts with 5 (uncompressed) or K (compressed)
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0A, // starts with 7Xh

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,
}

// RegressionNetParams defines the network parameters for the regression test
// Bitcoin network.  Not to be confused with the test Bitcoin network (version
// 3), this network is sometimes simply called "testnet".
var RegressionNetParams = Params{
	Name:        "regtest",
	Net:         wire.TestNet,
	DefaultPort: "18444",
	DNSSeeds:    []DNSSeed{},

	// Chain parameters
	GenesisBlock:             &regTestGenesisBlock,
	GenesisHash:              &regTestGenesisHash,
	PowLimit:                 regressionPowLimit,
	PowLimitBits:             0x207fffff,
	CoinbaseMaturity:         100,
	BIP0034Height:            100000000, // Not active - Permit ver 1 blocks
	BIP0065Height:            1351,      // Used by regression tests
	BIP0066Height:            1251,      // Used by regression tests
	SubsidyReductionInterval: 150,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 108, // 75%  of MinerConfirmationWindow
	MinerConfirmationWindow:       144,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "bcrt", // always bcrt for reg test net

	// Address encoding magics
	PubKeyHashAddrID: 0x6f, // starts with m or n
	ScriptHashAddrID: 0xc4, // starts with 2
	PrivateKeyID:     0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}

// TestNet3Params defines the network parameters for the test Bitcoin network
// (version 3).  Not to be confused with the regression test network, this
// network is sometimes simply called "testnet".
var TestNet3Params = Params{
	Name:        "testnet3",
	Net:         wire.TestNet3,
	DefaultPort: "18333",
	DNSSeeds: []DNSSeed{
		{"testnet-seed.bitcoin.jonasschnelli.ch", true},
		{"testnet-seed.bitcoin.schildbach.de", false},
		{"seed.tbtc.petertodd.org", true},
		{"testnet-seed.bluematt.me", false},
	},

	// Chain parameters
	GenesisBlock:             &testNet3GenesisBlock,
	GenesisHash:              &testNet3GenesisHash,
	PowLimit:                 testNet3PowLimit,
	PowLimitBits:             0x1d00ffff,
	BIP0034Height:            21111,  // 0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8
	BIP0065Height:            581885, // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
	BIP0066Height:            330776, // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        false,

	AssumeValid: newHashFromStr("000000000000006433d1efec504c53ca332b64963c425395515b01977bd7b3b0"), // 1864000

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{546, newHashFromStr("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
		{100000, newHashFromStr("00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e")},
		{200000, newHashFromStr("0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2")},
		{300001, newHashFromStr("0000000000004829474748f3d1bc8fcf893c88be255e6d7f571c548aff57abf4")},
		{400002, newHashFromStr("0000000005e2c73b8ecb82ae2dbc2e8274614ebad7172b53528aba7501f5a089")},
		{500011, newHashFromStr("00000000000929f63977fbac92ff570a9bd9e7715401ee96f2848f7b07750b02")},
		{600002, newHashFromStr("000000000001f471389afd6ee94dcace5ccc44adc18e8bff402443f034b07240")},
		{700000, newHashFromStr("000000000000406178b12a4dea3b27e13b3c4fe4510994fd667d7c1e6a3f4dc1")},
		{800010, newHashFromStr("000000000017ed35296433190b6829db01e657d80631d43f5983fa403bfdb4c1")},
		{900000, newHashFromStr("0000000000356f8d8924556e765b7a94aaebc6b5c8685dcfa2b1ee8b41acd89b")},
		{1000007, newHashFromStr("00000000001ccb893d8a1f25b70ad173ce955e5f50124261bbbc50379a612ddf")},
		{1100007, newHashFromStr("00000000000abc7b2cd18768ab3dee20857326a818d1946ed6796f42d66dd1e8")},
		{1200007, newHashFromStr("00000000000004f2dc41845771909db57e04191714ed8c963f7e56713a7b6cea")},
		{1300007, newHashFromStr("0000000072eab69d54df75107c052b26b0395b44f77578184293bf1bb1dbd9fa")},
	},

	// UtreexoRootHints ordered from oldest to newest.
	UtreexoRootHints: []UtreexoRootHint{
		{546, newHashFromStr("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"),
			743, []*chainhash.Hash{
				newLeafHashFromStr("1ede449941ab9909b00cc30bd459eca2964d6f1643bfd526bbf2eb0a109045ad"),
				newLeafHashFromStr("8559c31701c90db56ce0bd351291c125224e871f948159dc17ce154b35e89641"),
				newLeafHashFromStr("1272e2efc68eef67113ae3de1aae6c8597f9b71c19d3fe5265c205f7d3dda3c6"),
				newLeafHashFromStr("cf594417f83db3cdecea39d0d0c7b355a10ce59dc618a2f0de83b2cc05745ece"),
				newLeafHashFromStr("208d8e603f7bc0afc1e5b8162560715669852123417cde86407f67f6d0179653"),
				newLeafHashFromStr("ba94eda4d73a26dcc36051c387d7b9cfb352f6e5b68172687a796cce0fc2f6f5"),
				newLeafHashFromStr("d3dd9e244260a179b99d190a919b99a35a550460cbdd605522713cfdbb98da44"),
			},
		},
		{100000, newHashFromStr("00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e"),
			274250, []*chainhash.Hash{
				newLeafHashFromStr("1f27a5bde3eac5cd6e6c9a382727dc440bec8e2d9995a0a668a4b5ce3cff5ffa"),
				newLeafHashFromStr("ee0a20088aca5ff9cec6d6af2e5bb8e63d0fa4d877e9202236bbf4753ce85957"),
				newLeafHashFromStr("16b52a4afe5b166ad7f5040a1c878d367d4b348fc573692d39926fb4d56cc900"),
				newLeafHashFromStr("b97079e56528cebb7d2935d7c16fc063ac74f5aa39729193ce125a32beb846e9"),
				newLeafHashFromStr("a1116a8fce189e9d33ee073102f15b6365e0bea565b61f7bb2dcb45b227087e2"),
				newLeafHashFromStr("d2b2086ab2e712e5fb3d642b6c1fef7f14a9eec2352887d9bcdd84a40bf8d3ba"),
				newLeafHashFromStr("a3969c93b208b4cd427edeb204af8d44ed053b2f899c021f02a2a294f6b58b90"),
				newLeafHashFromStr("6f9a213c6b8cd49730e120125fd3232f159990ad543374dae3b95289122ea598"),
				newLeafHashFromStr("a5022fb8133f0e368f3833464851376862ffac6d031dc0b0a3b9eac21fadaa2f"),
			},
		},
		{200000, newHashFromStr("0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2"),
			464695, []*chainhash.Hash{
				newLeafHashFromStr("f216fe2ce7971420f5690b8044706ef6799ef6d3027e6908ba575d58af51b09a"),
				newLeafHashFromStr("7cf02b8071b8316d090c94e66969fd7c07ef1e09fe48fd3f903c1de4e35abb18"),
				newLeafHashFromStr("38aa3b1da8cb6b783114b127070b57e2c71bfb554edf5cbb1a8be02bef4cf4e7"),
				newLeafHashFromStr("2260611466c393ed35ada0cff5bd9a76948aca67badeef0580c5424758bc521b"),
				newLeafHashFromStr("867b10ef41843011e9b63784c19629c23cbc4e1f0b7c8ee790c50b34e1edf6e4"),
				newLeafHashFromStr("1220773164e0022319cc070346cce8ba51ce04fd639f19fd29bf5407547455bb"),
				newLeafHashFromStr("4f9203ec947a2c7ac87f61ce70be5a8fe5020bfccc29aa0a937d9216131bc117"),
				newLeafHashFromStr("f48f5845c35d5c5f68d45f05d1944f28a488f996f7c0ea0628e316332d626c66"),
				newLeafHashFromStr("ac55e96ead0a80f525db68498e66f46a91cefd956fead05e25bf61605ddef63b"),
				newLeafHashFromStr("62ebde24676f5a22ae70a98d03436462615239cbeb04908e6ad0ed0f453d2a5c"),
				newLeafHashFromStr("0b322297cf836f7ada7f0808ba6e8ce64501e47a94b167ee23de752efff47213"),
				newLeafHashFromStr("76a7459e52f8a57375249f9b676662df1714a3fb19a0d99ed22323d6e5639e16"),
			},
		},
		{300001, newHashFromStr("0000000000004829474748f3d1bc8fcf893c88be255e6d7f571c548aff57abf4"),
			2626784, []*chainhash.Hash{
				newLeafHashFromStr("0437cc9e4deffcfc43e8e13a2164bc5e05b6ed938e6b7397a14000a4b2cb8154"),
				newLeafHashFromStr("dfb1a55d3f84b442168251d41c16ddfe9b0422c3f2c4ab2a845b71970d232b6e"),
				newLeafHashFromStr("1f709ba42178cda3c2dbe8b55225b79c910c5af4beca76523d59d90ece180974"),
				newLeafHashFromStr("611e66b27ceb8687353cb7bcd7bbf4374f694f8e9c6fbf295f64c710924c6ceb"),
				newLeafHashFromStr("14b1d6d402d67455a90f03424af76d47a80cefbcaf6cd3953585466a534ec09a"),
				newLeafHashFromStr("ab97796d0f2dedcb0b1ea2d1f5bd9748a1e37580ae2c3db93c55e578e42aa468"),
				newLeafHashFromStr("98102da3148a3fbe002a3f5936e6b2f016f70f50e0d5e1957d3b7d5c08424dc9"),
			},
		},
		{400002, newHashFromStr("0000000005e2c73b8ecb82ae2dbc2e8274614ebad7172b53528aba7501f5a089"),
			2981638, []*chainhash.Hash{
				newLeafHashFromStr("4c1c0557e5a1227a34368fe495d3a6580790e363d80ea9e4b43d413613b86be2"),
				newLeafHashFromStr("7e8fd69d384acf86d8b26e8ef6389c3d2a51a1ee802b1d4124b3f09a4a5ef9e0"),
				newLeafHashFromStr("9adc181336e61ac3c7284428a86318e13684d524df32db6ba4a77a96cc48f9c6"),
				newLeafHashFromStr("9d3b3b5f2804405c8dfd8d09176ea67c18b59075d8630acfe1faba6d5151064a"),
				newLeafHashFromStr("cd63e75ffffefebdeb9e304ab10538a8c4fb633b088062ce829148ab0ce74bf0"),
				newLeafHashFromStr("5f86a3172985ef1e4279fe94720198f0d9e96937b99fa25237de549525411a8e"),
				newLeafHashFromStr("1eec24192ed46f5157c218b7e639bbeb18a7bcf9cf855a1ab5281a6b2d50cba6"),
				newLeafHashFromStr("6530becd070316cc45a24e16e7a5fc18bb422ba16debf1eb717ee53738638284"),
				newLeafHashFromStr("e4d9ec14070b4d42d0e95b7ac64f22a469609c14248c4cddb58d8a377d6413a8"),
				newLeafHashFromStr("b8f1a8210f3ca0187d94d06cb2292af1c2daf4c5aeab3f5f8e3164fa095ba912"),
				newLeafHashFromStr("7449d3c9a2a9232ce2008709fbd491703ce021cc98cb18386cf7cca31cacfbfd"),
				newLeafHashFromStr("74c04f11550aac83210692b919e82ad337fbeb503d84841c5f0ff682047b58f5"),
				newLeafHashFromStr("07f6f3d36faa4149a54ba323c591e5a26a10dba860f99d146617ca172cb9b272"),
			},
		},
		{500011, newHashFromStr("00000000000929f63977fbac92ff570a9bd9e7715401ee96f2848f7b07750b02"),
			5447549, []*chainhash.Hash{
				newLeafHashFromStr("3dc2872e6d88c2644cb537d36ad20ae0de21a1a39c66363af52265bf818f4132"),
				newLeafHashFromStr("e42c0794eb82dde5d3176df23beabbd9850ee26548dc364c029db50cd0a22420"),
				newLeafHashFromStr("84431e17a7532f23aabaeb1b50fc3ee38374da20e850f895f83eedd9f60b8808"),
				newLeafHashFromStr("3d5d269bfacdd6d00bef0ade2591a053a51de58c7545828d97da326ebf0b5847"),
				newLeafHashFromStr("9572b94d7a61d25ff21461d6017c21350e72d48754812405f65ffc8c1c589698"),
				newLeafHashFromStr("093d329c1d035a67f3762aa679a1e6035142e01d5e148c4b072c214107109f90"),
				newLeafHashFromStr("14e7815111fb9646f0c2d27125633b1032e528461bfeea56127009607d513263"),
				newLeafHashFromStr("f3ae5ac482b0f5a336e60eec546a86cd2ab0d7adb013026ae47920003ebd6b90"),
				newLeafHashFromStr("564c27737949662f464d194821d7d024274862279fb66e80572fdb8dba87ba4d"),
				newLeafHashFromStr("bf3a2ff656e6d98b3d5efdb07561c2aa0ac913823d3ec74e50ef52831a8d73b7"),
				newLeafHashFromStr("c5632f0d2f126f3de784b9fa2846a11c8833ba02c820eafa268f83bf3f1d4812"),
				newLeafHashFromStr("36bc8413c43127c3ffabb9ef6ca0cfd0c0affc22a296cc5488abaf303c40d354"),
				newLeafHashFromStr("6277bba84d97ea2d9df0c242c4c7f5f1da43cd29d326eb9a4cf745c44addb823"),
				newLeafHashFromStr("5981703a91a370805696a4bcd81e45337ced8f6b90a84f84f7acd5e56f1be4fe"),
				newLeafHashFromStr("4a44382edeb7d5bf3a90dc3cdc5b72544c43f1b85c7c070601f2d11dd9702ef4"),
			},
		},
		{600002, newHashFromStr("000000000001f471389afd6ee94dcace5ccc44adc18e8bff402443f034b07240"),
			9126246, []*chainhash.Hash{
				newLeafHashFromStr("f7edecc27f7076022f62e8e93b9d67af2991f4313fd33db8cc4c56d262300aa1"),
				newLeafHashFromStr("a2ce9f6088b40a67d727b3e010b43cd4579481ead0528f156fbb9ecceac45894"),
				newLeafHashFromStr("b379701f8f70838676c21a357292d4d0eb2e9c835bb13f514a8abf5b17f42806"),
				newLeafHashFromStr("55310ea50c2361da6e844a5bf4904d8bc5d9eb667fd41c1f459e2879eb3b9383"),
				newLeafHashFromStr("584a07939ed538e97982c33f090f297fe04ed9ad727e22317e4d4b0f76e0ccc8"),
				newLeafHashFromStr("b3110d7cbee0970c72304e6b95416fa0a4ed84a7506b4d227e3ea941c1a8767b"),
				newLeafHashFromStr("7e0bbee0703a2d82cc768c9b2d93533ca6d7b4319e01512c922d79cae3642b9a"),
				newLeafHashFromStr("fb6ee7fd51f34bb54368c5b215a8e282af9584915cca51af65da110c67828eb5"),
				newLeafHashFromStr("db9b9004eb458af8b1d9af0309efc91353da9717afae69bcf6875cde6827ebe6"),
				newLeafHashFromStr("08e77351f9054d9edb1565551edf6ea2a48e2dafe9bb02e784c829f667c2e353"),
			},
		},
		{700000, newHashFromStr("000000000000406178b12a4dea3b27e13b3c4fe4510994fd667d7c1e6a3f4dc1"),
			14661600, []*chainhash.Hash{
				newLeafHashFromStr("0a15659f5c1cee481ccd0ea2fbd7de8ac09d9686ec515023c5500e591863483f"),
				newLeafHashFromStr("1418d924740cace1f126b2e134ff7243ef7f4b3134a6b08787cc651d91fe103e"),
				newLeafHashFromStr("77f077b0d5e2cf86c848f4edb44e890bba131969cc79aeb5ff3023adf064d413"),
				newLeafHashFromStr("c1c37e2946aaeacaae3962bc5f773f044d828cd1f2ef373dcf334ba67d5bf45b"),
				newLeafHashFromStr("73ab0440b86180155341399fecf28b4192372a5e3b51fa99ff030613599062d4"),
				newLeafHashFromStr("2763b6bfe2e1c7c1475ee93f274233ab7c39bb70686741f3bd34bc9e5d64b65b"),
				newLeafHashFromStr("f11cdf30eaaeb1e0496d83be37073978e46ef733dfe42972abac8c8d9d50f191"),
				newLeafHashFromStr("c8ff6964fc1c69a645f88ec5854b87b20ebba52e5765971de987325ca5c9244a"),
				newLeafHashFromStr("cfd14fcdc0b77ad890801354c70cd45ffa562ce38821b194c34e67c41c3fd134"),
				newLeafHashFromStr("11df3ae9ad2ea67c5690008e312ace5b84bd52f29bef8c38bc85922d8fee73e2"),
				newLeafHashFromStr("c139bbdfd7fc8b8a09b8b7a552a3dcc34a1f88eaf80efb2f43bdbcb57d45226c"),
				newLeafHashFromStr("e5974fb370453cda4fcbb83930a3383d9b6e325d7c313e0205afe0aed3085b21"),
				newLeafHashFromStr("36464043ae2d3e67162a3053128fed403427e102786ff0da1f0f77c2e0aacaa7"),
				newLeafHashFromStr("ab8332cde688fd696609927543f82e75b3aec4159a864bb9448e8c6f626c6233"),
				newLeafHashFromStr("814045182fefd402a7d5a01b918cce7ac9bf5eb97c2e60bf9459aae39179bbb2"),
				newLeafHashFromStr("e46f94d5e6575aa4160d780666d7adbcae783e84ccbf2c38e722c43613a7a221"),
			},
		},
		{725000, newHashFromStr("0000000000000d5163f0bc3e09a9f4c72c6386aa25f022bba4fffee601add7ef"),
			10595541, []*chainhash.Hash{
				newLeafHashFromStr("0a3a151a04701e4c64a1ddd4e506bb82c532ec025028ba6fbdafe9aa05968ea6"),
				newLeafHashFromStr("b5a728a81910084e533901f44eba34285599f75f44093f74a882b317dc5cc137"),
				newLeafHashFromStr("427f0d85cd9dd9f52d352f4ce954836c288205e8c2521ec5fe3d3919fcb2c532"),
				newLeafHashFromStr("44f57bba889c6f3b449cb87b0f50e6f2d9cc4540cc5c8b703d7f133a97bc97b2"),
				newLeafHashFromStr("45b66a568047fd1fc846bc88cf5d1cc8424d2bf7c80af0f28f641a4aa8b4f8f5"),
				newLeafHashFromStr("3e78f106056739a65ba57d4f1b4f90129a74b71138ba7f8ca5b508c1c73a7b4c"),
				newLeafHashFromStr("a01a62f7e2f7ee46299606b552afc1e12163f083457c097ee354a7cbd932dd66"),
				newLeafHashFromStr("3dfd32e35b3c5b49a1f4de4efa555a0caec6b2875412aa44970bd192548cafca"),
				newLeafHashFromStr("d590c5cef984a7833ba8342721c1f1060a269817e9029484dac3e7c97f7d95f1"),
				newLeafHashFromStr("a07f6067ca663a74c952e606a5ad83957603d2b28c5f55d8061e2a4da13c5c8c"),
				newLeafHashFromStr("7f98973294406cb452f77cfa2591b1bb6affc42f89307947b7715835c0a5d996"),
				newLeafHashFromStr("74756f78a2c08a68e9e77c1e4927eebb6d45a7ff9cef26d76906cf2a52a5bc2e"),
			},
		},
		{750001, newHashFromStr("0000000000664f3ee810b88057a2be961711f69c3caf248aeb7e652772e15fef"),
			10700418, []*chainhash.Hash{
				newLeafHashFromStr("052ac44e927a7f632f06e8dba47e53f0434ab51b94d8e07a6e8915ad199387f8"),
				newLeafHashFromStr("b282287e5ea86fd68b59ab8db42d3f3d212d4ab2d8cb7c75947d938fcbd5f178"),
				newLeafHashFromStr("7348ce0453e5770a65093f09214ffcfe91bcaf0099252cfb8d6a2bb34759e0c9"),
				newLeafHashFromStr("3e14c27b62b4ed49a1c453996b9c8201537e5aa8b363a48e66a87d4c54faa228"),
				newLeafHashFromStr("80397289416c71dd9e60c3c570f5c2383602c3a94972f3f4caa2ba8a7bfd85de"),
				newLeafHashFromStr("c5cb5d5cca9e82f68b2c71a75b914d151172562fd4312042f08017e052c8d760"),
				newLeafHashFromStr("b6157e8c7df7960b4b3b9244463b6998feb0ac5c8e524fb29fadcbbe04277cae"),
				newLeafHashFromStr("a9678b78b92df8056065017240e87fa7a0b379142868f1dbd8f0d4dee716f7ca"),
				newLeafHashFromStr("7efa18773bac85252ee324a050798610ec2fe4555c71734486d9d478e7ccaee4"),
			},
		},
		{800010, newHashFromStr("000000000017ed35296433190b6829db01e657d80631d43f5983fa403bfdb4c1"),
			10890162, []*chainhash.Hash{
				newLeafHashFromStr("e3fdc3f844a41c4d147e0f1cf913230e6f47c7db3518f39bc7ca088991fd9a19"),
				newLeafHashFromStr("a991203d74f53a0f73268b9ea339196efd59f4383d15c21b840f298e9e586a6b"),
				newLeafHashFromStr("3ac4f6890e630c7e20cba28be86562428351003173b949ac9d3bdd1ecfa9d1e8"),
				newLeafHashFromStr("37779fd07359552ad583ff4b8306f2a0698ff9327886ac55f89d19a3212b77d4"),
				newLeafHashFromStr("4d6053ab61928e59e6f9bf1988944ad1618c51cd0a7fab546e25ea6b5194f88a"),
				newLeafHashFromStr("2a14e8272ea3800cecbf2253e52fefe55449ffb8d0b5d628bbf5b5b77da27a62"),
				newLeafHashFromStr("fadf5577c58ae38dd93def7a2965d60902c26f811f56c8f503cb66c98483af0b"),
				newLeafHashFromStr("031b2172f8d43c54ab86af0b0ce1cd07c0dc63ad41f25caa9c48b49aa43c8583"),
				newLeafHashFromStr("91e87483dde0425d97b3632ea055b15a722573c8fdd4c89f27ba9892a3464722"),
				newLeafHashFromStr("7117325db9d84a81ce14c00c3a09a9ae7eaa9949de9f91c231b69ea26b454a9e"),
				newLeafHashFromStr("e466906ff6c2c8feb9f4bfc3c95bd06dd913786fa1d18dc0bdc6209ec1e8c526"),
				newLeafHashFromStr("426b44898b7a407d2335bfbe632c8713832219701fe17313c93f5654ad4b13a4"),
			},
		},
		{900000, newHashFromStr("0000000000356f8d8924556e765b7a94aaebc6b5c8685dcfa2b1ee8b41acd89b"),
			12385533, []*chainhash.Hash{
				newLeafHashFromStr("ee6941332c286a102a420add2502adb7851beb7d5d55b655847c8465cd4f76e5"),
				newLeafHashFromStr("21c47be845dafdfd0d5b60c2c1cf548bc396dbf710e61949a2392e4573af3100"),
				newLeafHashFromStr("a02a925be262d32276fb6b63300a3b71341386d8ca7fb39a4715e29cc52966e9"),
				newLeafHashFromStr("6bba999feb2d9bcf660c10410891912e4175bab789401694bac87d0dd3bb9e31"),
				newLeafHashFromStr("07c09cf14d25281e4b4e11b01886ef8a1edf264a8ba8c1daf41116f48efad173"),
				newLeafHashFromStr("477d96fb9eecbbad75f3d492d730fe49e95f5309e8e977cdcf1a3808919101dd"),
				newLeafHashFromStr("45b28726191279700fd3afcdfba2842dc16aa9731ba84346893195901d41530a"),
				newLeafHashFromStr("80fe0d34821964812cd003d116d28a671d8a9b3243412a76c6ac79bbe65bf1c0"),
				newLeafHashFromStr("75e728fc005dbf8e3b5594354c82163f958b89bf9c41cbba84fc5671aa1cac90"),
				newLeafHashFromStr("2b7ad04f3ec2ac6752e6c9b26e9afd38f974c21d00d982471425a12392582c69"),
				newLeafHashFromStr("e7204406399929d0a63e625d447ca0adb53643e4f0c658e407f049b89aef2695"),
				newLeafHashFromStr("bb31daa7453395710fa6a94de538e905610af5cfa58640b1670c10faffd9b313"),
				newLeafHashFromStr("2cc2c800fe82d344ecf81de21bc79f627503278392b9c167378cbb99efea0104"),
				newLeafHashFromStr("b4be81279c93f1ed0f5d9e30cbfb669d84ce05a6ed76f77850229ffcbb3c3728"),
				newLeafHashFromStr("5a01e9605a76dcda76df762638cd2df2ed7c6926ade46c032eafb1645e018459"),
				newLeafHashFromStr("4ce9431d73493546942e4488c72feebde655de9e7797344ba7c7019659d2cc1b"),
				newLeafHashFromStr("d20cce9e7e0d39854f4a315ec72e5278772da80385b55c4bad746984c3f2de33"),
				newLeafHashFromStr("f245f9a6e5721fc629b62bbf6071579217441270fdf799e9ee1a100823e42932"),
			},
		},
		{1000007, newHashFromStr("00000000001ccb893d8a1f25b70ad173ce955e5f50124261bbbc50379a612ddf"),
			13442701, []*chainhash.Hash{
				newLeafHashFromStr("50b03d53dd5ca83fd032f2eca88d8eeca1cf8df56ec5adc28e37701d3acc981e"),
				newLeafHashFromStr("014c445e0f662ceebf7d765cadf4ac512280c1173066b6729bf838c054eaccc7"),
				newLeafHashFromStr("cac25a0f606b5021b8ede6b7fe640ce787d3f2902c1b31d082a5ad54eebf6389"),
				newLeafHashFromStr("d223e3017fd40a4fc31d0d7cd3ec7b22fdeb16e200abbf9a97aa171108caab3e"),
				newLeafHashFromStr("e6031dc95a1e611b681d130843c54d4a6d814159005e6d401cc804ec7d65315f"),
				newLeafHashFromStr("39fa3ff40fc3b99738e371e2729542de3b16409f5fc7c77490c58e68185dff5e"),
				newLeafHashFromStr("845a2c4104b8166f7c3f1cc485ede25c81153a4def06927576ff51a6f0b72fad"),
				newLeafHashFromStr("9299a3464df3904a4ea9bad038b8d7e54f9c1743160801c8af86deb98528a124"),
				newLeafHashFromStr("ea829a92b6659eef22f4b47de0b6b61e4e74dbe2adbb6e63f12558026e1cface"),
				newLeafHashFromStr("9ffefa0896eeca6da51cdffb4581efa9ae3ef7be7d3537ec3f3c40f8df1317af"),
				newLeafHashFromStr("91e19af265c809dd079bd33e5e8c091fe504b7ad65e4b978d2ea14b5fc2a95cb"),
				newLeafHashFromStr("7f2798436c4d5c3c58a6ffbd3537fd5d9e5e9c10eba4b1055a251ade69068210"),
				newLeafHashFromStr("5f71991360396d091c8a516429436d7336d361e35c7c581a115cfba86a7f2cc9"),
			},
		},
		{1050000, newHashFromStr("00000000001aa0b431dc7f8fa75179b8440bdb671db5ca79e1087faff00c19d8"),
			13669369, []*chainhash.Hash{
				newLeafHashFromStr("f5516a591b3be01f1525b72e8210026894695bc245cdfcb40d5369a24617fdc1"),
				newLeafHashFromStr("fab43181d8af721f86024aacb2e7f45ac83c19f4a943a9a1b020657c17ae39ac"),
				newLeafHashFromStr("ea25cb97e10f57f7d01fa7cafb34ef60169ac5f272233ae087d937610a93eb4e"),
				newLeafHashFromStr("d7f2b26cff3c283c6a8bcbadc23f03abc952ab534217278dcf7e96131bc6768f"),
				newLeafHashFromStr("88e8e805256593cc594e38f5ed9ccc42cf56e3ad9ec77e46e71d19fad2b8c917"),
				newLeafHashFromStr("2749213e1ade222ac8185292972ce892681fbe5f50f25c7aeebfeb3663713e1b"),
				newLeafHashFromStr("508857c398865226fea5cf5a7ab5fe739e2edb874a16cc76aea9b891b9b1dec9"),
				newLeafHashFromStr("4e9673f05358c2170d959ef9667eabededffd19170f5be8faa3987a312d05a39"),
				newLeafHashFromStr("323d734bfcc6542e86127ef9e46dc147afa3cb2e1385ac6fb816bb593ca5b7c0"),
				newLeafHashFromStr("3304185730ce6339573f4177587d343a6db930f228068e7cf60ecd6c96ef9f6f"),
				newLeafHashFromStr("8fe86bada47dbaf8923db7422e4b017710629555d542e06eacd939f0881889b4"),
				newLeafHashFromStr("330a01723462a96cf5d97bc3db780c71612b2e7df61270a0524ff8a6fdd288ba"),
				newLeafHashFromStr("e66858352d04a38876138fa9195b36566be1b235042bcd6743ba774d47392fd4"),
			},
		},
		{1100007, newHashFromStr("00000000000abc7b2cd18768ab3dee20857326a818d1946ed6796f42d66dd1e8"),
			14139123, []*chainhash.Hash{
				newLeafHashFromStr("a03ebac79ddefccb3e0b060e4da0e988c69bec51756ba133d26ac5fa3e95b94d"),
				newLeafHashFromStr("7938b7dc6f6f85a9a0fdec0501f0624d96f8362a213d1f074fbeae196d02802a"),
				newLeafHashFromStr("e8a03e1996583a20c9a76ab0aaec493200b7a2cebb0109606adf30cabf398494"),
				newLeafHashFromStr("7bb449e2c30b798db6243483b61c91b6f69475aa28b7187a83fa20c643a5e940"),
				newLeafHashFromStr("87357b4f8364addea212c27554b34d65e7d35204f6bf6837932060032869676e"),
				newLeafHashFromStr("14f3f3ffd9f619c4d5fe25a41085aed33bca35a45cef8ca3ca702cd64049c5dc"),
				newLeafHashFromStr("9623945850a87acc64a6263d22d0e11c2cf0ab91c3f1b7f8afdc6f385ff86084"),
				newLeafHashFromStr("662956d1aa78a9920715f209bd506fd84cad36c9435bbfba2d2e51de5c55d4d1"),
				newLeafHashFromStr("eb100b59696b66043b49638fdfa327f6e6d511078e013b362028d38c2913f49f"),
				newLeafHashFromStr("f15d810e31fe48977f1b126a660b390db1e03b0146ec71ade75ab19c17b05d37"),
				newLeafHashFromStr("c210af493c08635dd3dca6627c78c7ccf77d64d81e6d2058fe5f3c056cdab23f"),
				newLeafHashFromStr("d5f0f577e356bf36ce6763243869a9708832d8c67a278b74d0dba8837169a89a"),
				newLeafHashFromStr("84320c1e886b54c027f41be79ac064e2b0b38ca009b1abc1e6d60bf9edd54640"),
				newLeafHashFromStr("fddaebee2b76df65a18f194197019a4981882aca488560853a11d1fb2fd4a243"),
				newLeafHashFromStr("7cce6c06fb2e1c1c9d3d891feb7bea33fe0b8d08c0569cb09bad0e41d1dd65c9"),
				newLeafHashFromStr("278d0307b759b937f93d93c6403df4e3d58ef78d8424e97dbf1f07c9d0391934"),
				newLeafHashFromStr("e22380ee9b87e7f00bffe940a25dddcd33598968d8293fd6449c6739beb7e218"),
				newLeafHashFromStr("327aa52bc72d9be9664d1642ae34fac76edb7eb29da06701f3ce89ee917b2376"),
			},
		},
		{1200007, newHashFromStr("00000000000004f2dc41845771909db57e04191714ed8c963f7e56713a7b6cea"),
			17796022, []*chainhash.Hash{
				newLeafHashFromStr("eb48720e3c71aa4b9bd121f5c59beaeb12a089990eecfd7190e880d0525d8c8c"),
				newLeafHashFromStr("434aceb53e78fbf3d450587347321ef4916d5fa910499f183616e096eb48f718"),
				newLeafHashFromStr("9b5ce9c13ad0d5a8650652450091b763b1f172d29275d29853b92940b1e305c4"),
				newLeafHashFromStr("35bd621f0eda28cb97bf34ee58d1bcfea1b3ac56a0e9344f6c66ec3cb039fa14"),
				newLeafHashFromStr("59617bf39c97a4607dc7530983727cfd124a878dd1ccbf23645a9d6b949d4c5c"),
				newLeafHashFromStr("b423daea8cf00e7de881edd71a4eb70ee3579eac7af61c070c87b06f9438936d"),
				newLeafHashFromStr("6bd2ab1a00692bff2a53f9a2031a671e3a0d8ac55bd49a99e9d537ebacb035aa"),
				newLeafHashFromStr("52aeb17e5c510046f969b636f024c9306261f68c7300b0b45bf1352f3c6bb301"),
				newLeafHashFromStr("7197456c1da8d7f8e251f3f3ca291201c78332e051fe1d320a886b061b144d2b"),
				newLeafHashFromStr("88e734bb9cd1e925518264993c8c4c85c43fa2fd532b81afc864afb0059b0681"),
				newLeafHashFromStr("5fae0ee12d9c0ff42f9b2681bd8219cae7a61cc9c1c07b3714a1b3ee6eef5ac3"),
				newLeafHashFromStr("82385f5d0b70c434a4cb21d187bf98330929e120cbaa2fba0419a2a105000522"),
				newLeafHashFromStr("c957e0328a0ea57fffed0b683c7a2f1eb8527e7034063e8d1977b64286427ec3"),
				newLeafHashFromStr("d622e48ae4f833ff6ae2ad539169f256c675f6416f210d00f66e711f589c0d74"),
			},
		},
		{1300007, newHashFromStr("0000000072eab69d54df75107c052b26b0395b44f77578184293bf1bb1dbd9fa"),
			19213279, []*chainhash.Hash{
				newLeafHashFromStr("703cc23bcd356694a6767c94e0169d29d47ec6a576e70bc52ac88b0cbdecb03b"),
				newLeafHashFromStr("4c8e7547caf753d663b91927859bba816fca871a164e260ba4597b4e8bb87b7f"),
				newLeafHashFromStr("753bd25a677efe322cbb6ab590f49392fe75f57527ba7e22210643c4781cfcd9"),
				newLeafHashFromStr("41bf2e7fe8bdc7707ecdb43d03f81747761303fb3f6b905756e279f1e91c07fa"),
				newLeafHashFromStr("ef97f96c4ba864dff96193cee5ef37e391a9b324b7983e186dc4eed3a6059b41"),
				newLeafHashFromStr("20a869f0b6d1156fc3d74229190722a72328edf813f93b2483021dfe6e231d2f"),
				newLeafHashFromStr("ef287ac9698077bcefd4ba727ee2c7d91b0b9479377c09f047f0907bdaac0f8f"),
				newLeafHashFromStr("78c49f7d9fb05a8be6abb2abe7e93c7ed32ac537a3029a7a033709455d9908f5"),
				newLeafHashFromStr("572046b8b80a35c7198a1bb5e18597d47359890351d070476b4eb352a113daff"),
				newLeafHashFromStr("df938a68ffa902cbb86ea56c58780ceb9aff9546fab17ff5b97327866b6eea60"),
				newLeafHashFromStr("38e912b09e7336df4a3382f00d795794963e18d8ba61d94c5e674471704297df"),
				newLeafHashFromStr("72b7bbe46fe5dee8d571e377c72e98e6feb5329ec6ad0964a2a54d0955301b30"),
				newLeafHashFromStr("c5d4b0e399a7143d817c255763b1e6843f6973704cda645f0d8e65f5c5f43219"),
				newLeafHashFromStr("17ad4b919d18dd7ca7c89ebed959645180bbb0ddd1e5d25fadcd61fe64b331d0"),
				newLeafHashFromStr("c34c928ea62b76fc2bdab5601ea3f12f9df4be5fd8bde3f4438156c10d11ad43"),
			},
		},
		{1350001, newHashFromStr("00000000000001d8749e414562930673bba5b5c53fbab3c8e9aeb3fc1e97920b"),
			19326735, []*chainhash.Hash{
				newLeafHashFromStr("95626bd9324495717ac054dcea5a1d4e7ed73d5d0d389263e7105314139df0bc"),
				newLeafHashFromStr("16b6b39b5c076a34e3d35380974cfc92949778bb7d9218c080d06e3a85058596"),
				newLeafHashFromStr("43037f2cd77c9a1dc80c02cffc606a0db470f04eaaf5f0c393609d15e1e4a7c5"),
				newLeafHashFromStr("e818e8ea5ca7e86a968691f950f5bee0eea342f6097781f42d777fa146a1fc1d"),
				newLeafHashFromStr("3c98b33973ede8fedeb79b96244e77eba9e8f322d91f9f90d5dde9cf2fb8c2c3"),
				newLeafHashFromStr("e40114cbb9af5ea2702e5fa645b1a203bc6e97a6367243f477f050043797fda6"),
				newLeafHashFromStr("586c3b491c2c251da7275eb851917fc9cb549558deb4dc982b73f158057d9dc3"),
				newLeafHashFromStr("c894913dac2887a1700b7e05def0500e5cad9a239e8e005978ee1112353925f3"),
				newLeafHashFromStr("0f69ace06dd40aca3efaad79491b859e79916d045b57a656311af58fcde5836b"),
				newLeafHashFromStr("a22b0305247411dea68abea149bebc354f18051c2d7f3fce5d08214eab3993af"),
				newLeafHashFromStr("61714e1de98c7a2397391deddd8ff5f613f19dc92bea6fd95db73d7f93154750"),
				newLeafHashFromStr("0d6ac74547e982e5ab425560deb67c5466199d39caf42093266247cd1b0665f5"),
				newLeafHashFromStr("46626b449de1ba2cbfd05d526e57cc7e1777875672b08c82e1da8c1524ad57d5"),
				newLeafHashFromStr("d26dc58c87f7c34410856fe8853280ffa4798ab835f47b31846975a276c6016f"),
			},
		},
		{1375000, newHashFromStr("00000000000010dfc82e5ec98ea56833263d1b582e3f2458ca80c6665c6731ed"),
			19601340, []*chainhash.Hash{
				newLeafHashFromStr("126d0ce13776f3d43d0d9e3785350dd031c1401ee70ea9f9b3b00cea3b93c6dc"),
				newLeafHashFromStr("938ab65fc4e9d6ea64b57c058b39ba92252a62b9972606be6b4f441b96ba9a70"),
				newLeafHashFromStr("02de027db0f0f088c9023989f00b2285271d9acbd1789d609df2103612d47ab5"),
				newLeafHashFromStr("79e38ff5de6163265ce7633a560efa445f0cd72f6b5af5c5068b9670716a1de1"),
				newLeafHashFromStr("3408417d6527574e15a00d24e7f8f523825c11eb77c3228a46cbae4584feebca"),
				newLeafHashFromStr("254661127eff3d95b647c56b87e9392204dfd2bf96f5dded3c0e7fad745fc111"),
				newLeafHashFromStr("d4b297452e05182902e60edd4591e391a91d6ef10c76c8f31960c2abe364301f"),
				newLeafHashFromStr("9797b85ac31a069ebd13f484780afed4a812078889223b87e24fc4ee8810fe38"),
				newLeafHashFromStr("07f09ad176124d705ff055a75d1bb13ee46d9e0f6b1414e7c9263a4f26701393"),
				newLeafHashFromStr("891a6f6df5a33ab03999234a10a82b1f7b356dbb4e97544cfbbdf88b1acb908a"),
				newLeafHashFromStr("8a8b5f4099d6ac14221f12f33f0748b54808ace6cfea26c270859bf726542da9"),
				newLeafHashFromStr("4a5449df82ff10bd4c6683af0de335cf81bb677a15855dd5169e728cb99b4d90"),
				newLeafHashFromStr("e52cb930c5733724ef24746efd6c485722ee8da8557b435bb2b235c5df8294ae"),
				newLeafHashFromStr("8a309c7edd977d501ff3a4c91a3615816d858247f18380839d4865dd57051a7b"),
			},
		},
		{1400007, newHashFromStr("000000000000e58ec4ddd29ebdaddd18fe50642050f9c7ecdae5c6c6381a1675"),
			19726544, []*chainhash.Hash{
				newLeafHashFromStr("86b64cdc902e1f0c66ffcb37d49608a9ae71d866275b2ccdc56b4799cf8cf040"),
				newLeafHashFromStr("dc726d094de2de4ce2f63d2170e205b10942d08a376d83a36308aa7c3d3bfc47"),
				newLeafHashFromStr("e46a66ed25450cf63fb03c466901bd61d003ee94b9c29cf861341632b8ff6d3c"),
				newLeafHashFromStr("a92f08fec04088f5ae6876c80434427f41d898907e36915580ac0390aed120ba"),
				newLeafHashFromStr("74951c160afb1224cf3d54510e575aaeda898525cf1ef5b2d8b89fc6b7f7dcf5"),
				newLeafHashFromStr("30e013d7bf9a7a067ece61743db580bec0919f3d21542c31ac85f622b80734f4"),
				newLeafHashFromStr("ef112e9e60751154c71b7d99d3ccc9bea7913540bfd5d4d7027d1090560df989"),
				newLeafHashFromStr("32a3865f24031bae025b5fe47cefd96f8341c67a6ddcdbddcc8c2573e7254876"),
			},
		},
		{1425000, newHashFromStr("00000000004d21ae54e61bfe4c0c6270c491201d255ad6000438a13a2760780f"),
			20321621, []*chainhash.Hash{
				newLeafHashFromStr("845aa97ebe6b04562860ac8b6f3b48e6871d1147da2bfa5ba80ce6a0bfbbac76"),
				newLeafHashFromStr("246db732743cf5f38fadccc19a0715e17d1381a29291b644635bc3f68a907959"),
				newLeafHashFromStr("b3626a4aaa63dbb9c24efc4ea132950030aad236614fbd483b8e2de4e4de40c9"),
				newLeafHashFromStr("e09b2622b1b1f246b828db3fe7acedc011cef746a2249a4a5b78edb2b83aa590"),
				newLeafHashFromStr("aa60fe9b8bc8aed20bb92e7e538d305318a3ec5ba78b4b6c69656be775455627"),
				newLeafHashFromStr("f9e665da8dfa040b37be0271b7ff7aaabb3ff3b6be43d94004ab5318e1238bcc"),
				newLeafHashFromStr("bf304e4b73cad01c8716e0737a12e765ac2da0943df54443d971353ba800b24e"),
				newLeafHashFromStr("e92fe9db161f7d803b832b61985459ab2f8a4eb3c6d3d1645e58dcf7d2413be9"),
				newLeafHashFromStr("204bcfe260b343ab95cea155c77fc33be58f83cfbe008cbeccb2792bfbe6da47"),
				newLeafHashFromStr("6b94078a88c9af8dbf75589030305d8e604fe436790d9db399ee3f00d72b7ec2"),
				newLeafHashFromStr("2a001e0076da6e4163f72bcae8bdf42c8657de1519dc17d1abffd0b53576890b"),
				newLeafHashFromStr("e82a50dde2b9e49b84148b6a3164e81eecd505f166222becba84915f17adcd2a"),
			},
		},
		{1450001, newHashFromStr("00000000000000b6229b9c79af87b86142b02690393b54ca7e4dbcbab0516fce"),
			20743408, []*chainhash.Hash{
				newLeafHashFromStr("6d92c9e5a372addcc674aaa24c4a67cc010e12ca45a56d2637394d4f76e1d4b8"),
				newLeafHashFromStr("072c7783a8adad4c793a37f64750717f8bee635f0b19dda8752c3586dd114987"),
				newLeafHashFromStr("f5af2041ae8fa9016cf07a2d6b1d90a6c751599113dc7560429ae6a8167966d5"),
				newLeafHashFromStr("7effda9752f6a27a17b1f52e6301237194cdef4535358d0afb469b33093b029e"),
				newLeafHashFromStr("0d593aef4bf4be2f20bd394d28c4d91230b8b85f058cb066010d0b362d0e7e79"),
				newLeafHashFromStr("b3973df80c02453c1d1ecd82fe1e0d1b1f5e6b8682244a402ac82034d6055ea5"),
				newLeafHashFromStr("f9fbadda98a40754c064e478457bbecfd21dfcb9d0c27810bdbccedc855858b3"),
				newLeafHashFromStr("06d4da1d6abf90616bcfcf6d91c495bd875679772a045c8cc214b51710213d54"),
				newLeafHashFromStr("a77c218f11823e986c2fbcae04120313328f20bb1557e33ff8199678e187788a"),
				newLeafHashFromStr("2e669075011085b8d2ef2123b0cd03464c49fc8907c0a7a66fc5c8e2b633c2cf"),
				newLeafHashFromStr("3fe16b4a3100dd40df9977a1e31b25856f5e567d0b01d717cf6123796720e24d"),
			},
		},
		{1500007, newHashFromStr("00000000000778da41b036e6f8ae2c82f143a8e28cddf4bf1141d2624e88f598"),
			21358714, []*chainhash.Hash{
				newLeafHashFromStr("add65c165c31c72b8ae6f847fcc6ae8ad1c26337ecf590a648cef6e23fbdbd27"),
				newLeafHashFromStr("e93f5f31456ab81bb8dc6de5bfc32a56ae8b1c8e75f73c6f995d4780d79560a4"),
				newLeafHashFromStr("efe19e6d662a849c8eed9df58aaf639d25c49feaf8b525637ed54299c0fdb080"),
				newLeafHashFromStr("b963a7cf73a851651474008b72fc77be26294fb61d4afed4925713b4316b783a"),
				newLeafHashFromStr("4af5033d4ac05f0e9ef7db7ce29e3bf7a7ad84c9e4e9613dd363af76a5c6ebb7"),
				newLeafHashFromStr("37608d3bc57b6f212b802da6c43e4a69a2af20346b2035e2ef04e19d1411fcdb"),
				newLeafHashFromStr("8f94afba7e20265015005a740d807b46c0f158b72cf67d1011db4c9915ce8e86"),
				newLeafHashFromStr("1e99556f72d7fb5e465351c223f5c93d14a9525d540238b617914e60e757d8e9"),
				newLeafHashFromStr("9c60fb68b91254cc57a65bb96eeea18d80637b4fc6c5b884591f2201c35d086a"),
				newLeafHashFromStr("74054a3bd2663ddb7eaa99cac3818c2d809789cd76d5a76f1db3b364b19dc6ce"),
				newLeafHashFromStr("f44d871dd42b8bddc30b88a1482c2136daaf9f22fcacc08a70759cf6d6155914"),
				newLeafHashFromStr("ca23610e18918ea0e413c740ad6deb67a8eb560793d3c11a30b5cb245e28a262"),
				newLeafHashFromStr("27e1308bf31351c486019b98b83f2fe8f9a31e0a225ea4ff7429132184d4aab4"),
			},
		},
		{1600007, newHashFromStr("000000000003ab0665299d6df8c170b0e0daa00ca1ec54028983f751652942e3"),
			23001051, []*chainhash.Hash{
				newLeafHashFromStr("c2fd554819baea7da921da91b6e55cd3e672e0c14768460d319563d6aef11d97"),
				newLeafHashFromStr("83c3e875fede531f98eca64094be674fb5917da7820758e3bbfec8bd82053428"),
				newLeafHashFromStr("4f66a176066cd0013b5ec721d0c52ba3abdb00c7f32b4e0ea3eaf81143918993"),
				newLeafHashFromStr("838989ee7314d3067e06c4021fe8d28c409d50dd5657f9bd41758b1f8ea007a8"),
				newLeafHashFromStr("a1a892dcac02dde21a590299f9791702d0ef64f986e4dae250652bec3de187dd"),
				newLeafHashFromStr("0b52a8fe19d992866b3401ab35de86d0f29892f42274d1a9c39f187ba96f8e34"),
				newLeafHashFromStr("d11520a28375c084af9d366711f929c014e46d76313a4ac4ab5aec3652a706c4"),
				newLeafHashFromStr("13ae81d23f5a94d9148d24d6051c3e146979a750e24e9cfa91830bccc9562776"),
				newLeafHashFromStr("fc9c40a7b77ad1529e562b4b3a61823696a6c832b3931d5eb094bcc88d119679"),
				newLeafHashFromStr("07916a3cd713157b329c8130fe8beb77652b9d1888bb9bcaed96bbb765e43d73"),
				newLeafHashFromStr("52746f186fca17c236b094d2e764d7ef8cb0960b90f3b89577512dc2b916333e"),
				newLeafHashFromStr("936fdb5a54846342cd41f12c089701c59db6ccfcd78b4a435870882b45e518f3"),
				newLeafHashFromStr("5192d7b9611c636b47a4111590663549ef7102f966791560b8b79e644dd9ad1c"),
				newLeafHashFromStr("a4e50f84c148f1ab5b7a32ffcecd1cf724bed338a98e39d0c1bd3f7bc37b8c96"),
				newLeafHashFromStr("7a085b3c24920e869bfea9efe6252c8c05511ff1d52eaa09da75238e9688c8bf"),
				newLeafHashFromStr("c8e4e55c333a32ff342b556c051079ba418b77ba93ec34cc4c585aaa4532498d"),
				newLeafHashFromStr("cf3bbb4a7f15ffb3f79ca8b77e9160104636badb209d6543c361fa6a87bc6bc3"),
				newLeafHashFromStr("83348ebeb93384740c0195058896a996b561eb085d52076f8fd730a6fc23824a"),
				newLeafHashFromStr("0f38c464e1086858bf30badd92194cb10c20881b54cab65587cf0a707e84df4f"),
			},
		},
		{1700007, newHashFromStr("00000000000284e57a71e65d8c647a01cbdc48b551a0e3af8864e3f7563d2273"),
			23665890, []*chainhash.Hash{
				newLeafHashFromStr("b87a90bfbc180969a731026bc8af224ee5d4e78585c78089f1164687b34814e4"),
				newLeafHashFromStr("9425b34ce6de8f6d2021fb21fe3e427a5858f26cdeb29d1a696b099b04ffb3a0"),
				newLeafHashFromStr("3520d08b6eb4de74ba0430f343ee4fa714a1260c3e986e743d82e3c4493fc086"),
				newLeafHashFromStr("6f438b286df299de63070a679239f95efee4f769261e606e31313c7cf44be94d"),
				newLeafHashFromStr("6b30c3a2a68b92ca29cf83a1108adb1f9f68fa74bc213a01f6a3bfb6ec013215"),
				newLeafHashFromStr("5174c3ecf576a67731e5b513630770b574175b9bfb5f0373a49befd797103542"),
				newLeafHashFromStr("3ca9bebfbab602bea5d49a7c711028a144b40a61b6853656849b3a4c058c094f"),
				newLeafHashFromStr("4b11a282cc9eb0fd161f5e72a33b5576fa1d274f1ba1eb7f15b39a4975b04a67"),
				newLeafHashFromStr("ad8d04622f569fca7cbca4117c081b8c8ad8b0c51cca83c0c1866d3f8c8d6306"),
				newLeafHashFromStr("8827d8948e956a3472abedb0bd85f75aba6c0ea7a686a3b643214a68d4df7f0d"),
				newLeafHashFromStr("f2a2d874f72a188d2a61136962bb32975c4c4f9bff734dc1f502ee865449fb57"),
				newLeafHashFromStr("f565ea59b0c014cd17c846a6fb000a8aa6e28eb073cf3f4638e547cba42bb248"),
			},
		},
		{1800007, newHashFromStr("00000000000015dd7fb287593a83ebdcefa6a9113c7a803bad2ebb6bcbdb7613"),
			23990602, []*chainhash.Hash{
				newLeafHashFromStr("8f3b06fa369098ce6586c8d7297f9e44aa5f8ef6a90772f87a312234b11d4b32"),
				newLeafHashFromStr("ee33007cb628e0a98e84504c0bac50edd9b91959f74140083b6167310513ca01"),
				newLeafHashFromStr("9a06d4e7e136fb2fe5ce15f6b28d2417e5ee038b9c8e89aa5800cda01ca73c39"),
				newLeafHashFromStr("73aa3cbfe591b7f59ba5fd994c7325d07029b6e2931b7b20e9fecd2173f184b3"),
				newLeafHashFromStr("4446c653a7713d72f7620919df92864f27ac9b4a13d4f093c005805a173fb276"),
				newLeafHashFromStr("bf7e608b1d630174cad92c919fd0fa3ddf398f38ed5becde45a6495fcf23cd51"),
				newLeafHashFromStr("bc5e7796a52d5c0ed96421af123d3641319caffbef029b49b0b1d97ea57b9b43"),
				newLeafHashFromStr("9d12caf6e23a03424b4274ba8ef2be21e6afab95ce3fea8218c2caacc1cf02b3"),
				newLeafHashFromStr("b2b44cea7f37cb2f48621c4d500c643417121af8dc126552a4d39eedeb667f1c"),
				newLeafHashFromStr("6d1287df544b65e30fbf4854a872afd49a9b9c9487c3997875ca7ddaee5863e5"),
				newLeafHashFromStr("92db62ebd4e4c68c3416b1384d149ca6a97564e82834749f3e6b0be61273deb1"),
			},
		},
		{1906000, newHashFromStr("000000000000000bb0685b98fd236473d5fccff2c76c7b05ba041a5fa38787d0"),
			24988685, []*chainhash.Hash{
				newLeafHashFromStr("5db9664dbb6a9b009b4ef353bd8b4777701f2507d89474eb9e377dbac1f36c6c"),
				newLeafHashFromStr("4477ca4062cb37e898658d74c949fd36ecc6bbc50c497e4ba31ca24f9039a2c3"),
				newLeafHashFromStr("701667db8956b8cbd22fc6ed4154b83b83eec28ea732ed1ce44d2a668d02edc7"),
				newLeafHashFromStr("0673669ddc169424d112d95c6a595ada34733b090232db0c037dc58379071e13"),
				newLeafHashFromStr("bef85bab287f41edd135f871964450f8ba505a46cbbf522fad062a50a13a22fb"),
				newLeafHashFromStr("6ae4b15b8e41367db617849bc61b69c2b0c6da33c6368679741ab0727b4ca678"),
				newLeafHashFromStr("af58f16186e64e5b698ffef89583f67915b2b4048d88031b0a78ce8c184b6ae6"),
				newLeafHashFromStr("1e1ffa38f96a07523507046569d395bc215c481ad7055b1beede4201302f8d01"),
				newLeafHashFromStr("4d214d53f0ce84e85777b47304de5877356d8920b2dd666ba8037fd356d3bc92"),
				newLeafHashFromStr("cc2589d93c64940ca6510936bf37dccb31dedce52259edd488d5956f2c2253b1"),
				newLeafHashFromStr("d77ab04eca3760e763a59c08b7d6c793af71c76b6b16c8f83f5d43c606cd2e10"),
				newLeafHashFromStr("f519a69fc4206353c97068077ab59ee0f4dbcc9ec41d63581922754f7d31b1b4"),
				newLeafHashFromStr("e4e5baff1bdc2f9b2b9ae62840f0ef0b6ee8960571049c0142f0b0f6e44c92e9"),
			},
		},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1512, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       2016,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  1199145601, // January 1, 2008 UTC
			ExpireTime: 1230767999, // December 31, 2008 UTC
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  1456790400, // March 1st, 2016
			ExpireTime: 1493596800, // May 1st, 2017
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  1462060800, // May 1, 2016 UTC
			ExpireTime: 1493596800, // May 1, 2017 UTC.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "tb", // always tb for test net

	// Address encoding magics
	PubKeyHashAddrID:        0x6f, // starts with m or n
	ScriptHashAddrID:        0xc4, // starts with 2
	WitnessPubKeyHashAddrID: 0x03, // starts with QW
	WitnessScriptHashAddrID: 0x28, // starts with T7n
	PrivateKeyID:            0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}

// SimNetParams defines the network parameters for the simulation test Bitcoin
// network.  This network is similar to the normal test network except it is
// intended for private use within a group of individuals doing simulation
// testing.  The functionality is intended to differ in that the only nodes
// which are specifically specified are used to create the network rather than
// following normal discovery rules.  This is important as otherwise it would
// just turn into another public testnet.
var SimNetParams = Params{
	Name:        "simnet",
	Net:         wire.SimNet,
	DefaultPort: "18555",
	DNSSeeds:    []DNSSeed{}, // NOTE: There must NOT be any seeds.

	// Chain parameters
	GenesisBlock:             &simNetGenesisBlock,
	GenesisHash:              &simNetGenesisHash,
	PowLimit:                 simNetPowLimit,
	PowLimitBits:             0x207fffff,
	BIP0034Height:            0, // Always active on simnet
	BIP0065Height:            0, // Always active on simnet
	BIP0066Height:            0, // Always active on simnet
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 75, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       100,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "sb", // always sb for sim net

	// Address encoding magics
	PubKeyHashAddrID:        0x3f, // starts with S
	ScriptHashAddrID:        0x7b, // starts with s
	PrivateKeyID:            0x64, // starts with 4 (uncompressed) or F (compressed)
	WitnessPubKeyHashAddrID: 0x19, // starts with Gg
	WitnessScriptHashAddrID: 0x28, // starts with ?

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x20, 0xb9, 0x00}, // starts with sprv
	HDPublicKeyID:  [4]byte{0x04, 0x20, 0xbd, 0x3a}, // starts with spub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 115, // ASCII for s
}

var (
	// ErrDuplicateNet describes an error where the parameters for a Bitcoin
	// network could not be set due to the network already being a standard
	// network or previously-registered into this package.
	ErrDuplicateNet = errors.New("duplicate Bitcoin network")

	// ErrUnknownHDKeyID describes an error where the provided id which
	// is intended to identify the network for a hierarchical deterministic
	// private extended key is not registered.
	ErrUnknownHDKeyID = errors.New("unknown hd private extended key bytes")

	// ErrInvalidHDKeyID describes an error where the provided hierarchical
	// deterministic version bytes, or hd key id, is malformed.
	ErrInvalidHDKeyID = errors.New("invalid hd extended key version bytes")
)

var (
	registeredNets       = make(map[wire.BitcoinNet]struct{})
	pubKeyHashAddrIDs    = make(map[byte]struct{})
	scriptHashAddrIDs    = make(map[byte]struct{})
	bech32SegwitPrefixes = make(map[string]struct{})
	hdPrivToPubKeyIDs    = make(map[[4]byte][]byte)
)

// String returns the hostname of the DNS seed in human-readable form.
func (d DNSSeed) String() string {
	return d.Host
}

// Register registers the network parameters for a Bitcoin network.  This may
// error with ErrDuplicateNet if the network is already registered (either
// due to a previous Register call, or the network being one of the default
// networks).
//
// Network parameters should be registered into this package by a main package
// as early as possible.  Then, library packages may lookup networks or network
// parameters based on inputs and work regardless of the network being standard
// or not.
func Register(params *Params) error {
	if _, ok := registeredNets[params.Net]; ok {
		return ErrDuplicateNet
	}
	registeredNets[params.Net] = struct{}{}
	pubKeyHashAddrIDs[params.PubKeyHashAddrID] = struct{}{}
	scriptHashAddrIDs[params.ScriptHashAddrID] = struct{}{}

	err := RegisterHDKeyID(params.HDPublicKeyID[:], params.HDPrivateKeyID[:])
	if err != nil {
		return err
	}

	// A valid Bech32 encoded segwit address always has as prefix the
	// human-readable part for the given net followed by '1'.
	bech32SegwitPrefixes[params.Bech32HRPSegwit+"1"] = struct{}{}
	return nil
}

// mustRegister performs the same function as Register except it panics if there
// is an error.  This should only be called from package init functions.
func mustRegister(params *Params) {
	if err := Register(params); err != nil {
		panic("failed to register network: " + err.Error())
	}
}

// IsPubKeyHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-pubkey-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsScriptHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsPubKeyHashAddrID(id byte) bool {
	_, ok := pubKeyHashAddrIDs[id]
	return ok
}

// IsScriptHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-script-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsPubKeyHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsScriptHashAddrID(id byte) bool {
	_, ok := scriptHashAddrIDs[id]
	return ok
}

// IsBech32SegwitPrefix returns whether the prefix is a known prefix for segwit
// addresses on any default or registered network.  This is used when decoding
// an address string into a specific address type.
func IsBech32SegwitPrefix(prefix string) bool {
	prefix = strings.ToLower(prefix)
	_, ok := bech32SegwitPrefixes[prefix]
	return ok
}

// RegisterHDKeyID registers a public and private hierarchical deterministic
// extended key ID pair.
//
// Non-standard HD version bytes, such as the ones documented in SLIP-0132,
// should be registered using this method for library packages to lookup key
// IDs (aka HD version bytes). When the provided key IDs are invalid, the
// ErrInvalidHDKeyID error will be returned.
//
// Reference:
//   SLIP-0132 : Registered HD version bytes for BIP-0032
//   https://github.com/satoshilabs/slips/blob/master/slip-0132.md
func RegisterHDKeyID(hdPublicKeyID []byte, hdPrivateKeyID []byte) error {
	if len(hdPublicKeyID) != 4 || len(hdPrivateKeyID) != 4 {
		return ErrInvalidHDKeyID
	}

	var keyID [4]byte
	copy(keyID[:], hdPrivateKeyID)
	hdPrivToPubKeyIDs[keyID] = hdPublicKeyID

	return nil
}

// HDPrivateKeyToPublicKeyID accepts a private hierarchical deterministic
// extended key id and returns the associated public key id.  When the provided
// id is not registered, the ErrUnknownHDKeyID error will be returned.
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// newHashFromStr converts the passed big-endian hex string into a
// chainhash.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		// Ordinarily I don't like panics in library code since it
		// can take applications down without them having a chance to
		// recover which is extremely annoying, however an exception is
		// being made in this case because the only way this can panic
		// is if there is an error in the hard-coded hashes.  Thus it
		// will only ever potentially panic on init and therefore is
		// 100% predictable.
		panic(err)
	}
	return hash
}

func init() {
	// Register all default networks when the package is initialized.
	mustRegister(&MainNetParams)
	mustRegister(&TestNet3Params)
	mustRegister(&RegressionNetParams)
	mustRegister(&SimNetParams)
}
