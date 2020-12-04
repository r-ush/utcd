// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/mit-dci/utreexo/accumulator"
	"github.com/mit-dci/utreexo/btcacc"
	"github.com/mit-dci/utreexo/util"
)

type UtreexoViewpoint struct {
	accumulator accumulator.Pollard
	entries     map[chainhash.Hash]*btcacc.LeafData
	bestHash    chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (uview *UtreexoViewpoint) BestHash() *chainhash.Hash {
	return &uview.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (uview *UtreexoViewpoint) SetBestHash(hash *chainhash.Hash) {
	uview.bestHash = *hash
}

func (uview *UtreexoViewpoint) Modify(ub *btcutil.UBlock) error {
	err := uview.accumulator.IngestBatchProof(ub.MsgUBlock().UtreexoData.AccProof)
	if err != nil {
		return err
	}
	fmt.Println("UTREEXO PROOF VERIFIED", uview.accumulator)

	remember := make([]bool, len(ub.MsgUBlock().UtreexoData.TxoTTLs))
	for i, ttl := range ub.MsgUBlock().UtreexoData.TxoTTLs {
		// ttl-ub.Height is the number of blocks until the block is spend.
		remember[i] = ttl < uview.accumulator.Lookahead
	}

	inskip, outskip := DedupeBlock(&ub.MsgUBlock().MsgBlock)

	nl, h := uview.accumulator.ReconstructStats()

	err = ub.ProofSanity(inskip, nl, h)
	if err != nil {
		return fmt.Errorf(
			"uData missing utxo data for block %d err: %e", ub.MsgUBlock().UtreexoData.Height, err)
	}

	leaves := BlockToAddLeaves(ub.MsgUBlock().MsgBlock, remember, outskip, ub.MsgUBlock().UtreexoData.Height)

	uview.accumulator.Modify(leaves, ub.MsgUBlock().UtreexoData.AccProof.Targets)

	fmt.Println("ACC STATE", uview.accumulator)
	return nil
}

/*
// ProofSanity checks the consistency of a UBlock.  Does the proof prove
// all the inputs in the block?
func (ub *UBlock) ProofSanity(inputSkipList []uint32, nl uint64, h uint8) error {
	// get the outpoints that need proof
	proveOPs := util.BlockToDelOPs(&ub.Block, inputSkipList)

	// ensure that all outpoints are provided in the extradata
	if len(proveOPs) != len(ub.UtreexoData.Stxos) {
		err := fmt.Errorf("height %d %d outpoints need proofs but only %d proven\n",
			ub.UtreexoData.Height, len(proveOPs), len(ub.UtreexoData.Stxos))
		return err
	}
	for i, _ := range ub.UtreexoData.Stxos {
		if btcacc.Hash(proveOPs[i].Hash) != ub.UtreexoData.Stxos[i].TxHash ||
			proveOPs[i].Index != ub.UtreexoData.Stxos[i].Index {
			err := fmt.Errorf("block/utxoData mismatch %s v %s\n",
				proveOPs[i].String(), ub.UtreexoData.Stxos[i].OPString())
			return err
		}
	}
	// derive leafHashes from leafData
	if !ub.UtreexoData.ProofSanity(nl, h) {
		return fmt.Errorf("height %d LeafData / Proof mismatch", ub.UtreexoData.Height)
	}

	return nil
}
*/

// DedupeBlock takes a bitcoin block, and returns two int slices: the indexes of
// inputs, and idexes of outputs which can be removed.  These are indexes
// within the block as a whole, even the coinbase tx.
// So the coinbase tx in & output numbers affect the skip lists even though
// the coinbase ins/outs can never be deduped.  it's simpler that way.
func DedupeBlock(blk *wire.MsgBlock) (inskip []uint32, outskip []uint32) {

	var i uint32
	// wire.Outpoints are comparable with == which is nice.
	inmap := make(map[wire.OutPoint]uint32)

	// go through txs then inputs building map
	for cbif0, tx := range blk.Transactions {
		if cbif0 == 0 { // coinbase tx can't be deduped
			i++ // coinbase has 1 input
			continue
		}
		for _, in := range tx.TxIn {
			// fmt.Printf("%s into inmap\n", in.PreviousOutPoint.String())
			inmap[in.PreviousOutPoint] = i
			i++
		}
	}

	i = 0
	// start over, go through outputs finding skips
	for cbif0, tx := range blk.Transactions {
		if cbif0 == 0 { // coinbase tx can't be deduped
			i += uint32(len(tx.TxOut)) // coinbase can have multiple inputs
			continue
		}
		txid := tx.TxHash()

		for outidx, _ := range tx.TxOut {
			op := wire.OutPoint{Hash: txid, Index: uint32(outidx)}
			// fmt.Printf("%s check for inmap... ", op.String())
			inpos, exists := inmap[op]
			if exists {
				// fmt.Printf("hit")
				inskip = append(inskip, inpos)
				outskip = append(outskip, i)
			}
			// fmt.Printf("\n")
			i++
		}
	}
	// sort inskip list, as it's built in order consumed not created
	sortUint32s(inskip)
	return
}

// it'd be cool if you just had .sort() methods on slices of builtin types...
func sortUint32s(s []uint32) {
	sort.Slice(s, func(a, b int) bool { return s[a] < s[b] })
}

// BlockToAdds turns all the new utxos in a msgblock into leafTxos
// uses remember slice up to number of txos, but doesn't check that it's the
// right length.  Similar with skiplist, doesn't check it.
func BlockToAddLeaves(blk wire.MsgBlock,
	remember []bool, skiplist []uint32,
	height int32) (leaves []accumulator.Leaf) {

	var txonum uint32
	// bh := bl.Blockhash
	for coinbaseif0, tx := range blk.Transactions {
		// cache txid aka txhash
		txid := tx.TxHash()
		for i, out := range tx.TxOut {
			// Skip all the OP_RETURNs
			if util.IsUnspendable(out) {
				txonum++
				continue
			}
			// Skip txos on the skip list
			if len(skiplist) > 0 && skiplist[0] == txonum {
				skiplist = skiplist[1:]
				txonum++
				continue
			}

			var l btcacc.LeafData
			// TODO put blockhash back in -- leaving empty for now!
			// l.BlockHash = bh
			l.TxHash = btcacc.Hash(txid)
			l.Index = uint32(i)
			l.Height = height
			if coinbaseif0 == 0 {
				l.Coinbase = true
			}
			l.Amt = out.Value
			l.PkScript = out.PkScript
			uleaf := accumulator.Leaf{Hash: l.LeafHash()}
			if uint32(len(remember)) > txonum {
				uleaf.Remember = remember[txonum]
			}
			leaves = append(leaves, uleaf)
			txonum++
		}
	}
	return
}

func NewUtreexoViewpoint() *UtreexoViewpoint {
	return &UtreexoViewpoint{
		entries:     make(map[chainhash.Hash]*btcacc.LeafData),
		accumulator: accumulator.Pollard{},
	}
}
