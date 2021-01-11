// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/mit-dci/utreexo/accumulator"
	"github.com/mit-dci/utreexo/btcacc"
)

type UtreexoViewpoint struct {
	accumulator accumulator.Pollard
	//entries     map[chainhash.Hash]*btcacc.LeafData
	bestHash chainhash.Hash
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

// Modify takes an ublock and adds the utxos and deletes the stxos from the utreexo state
func (uview *UtreexoViewpoint) Modify(ub *btcutil.UBlock) error {
	inskip, outskip := DedupeBlock(ub.Block())

	nl, h := uview.accumulator.ReconstructStats()

	err := ub.ProofSanity(inskip, nl, h)
	if err != nil {
		panic(err)
		//return err
		//return fmt.Errorf(
		//	"uData missing utxo data for block %d err: %e", ub.Block().Height(), err)
	}

	err = uview.accumulator.IngestBatchProof(ub.MsgUBlock().UtreexoData.AccProof)
	if err != nil {
		panic(err)
		//return err
	}

	remember := make([]bool, len(ub.MsgUBlock().UtreexoData.TxoTTLs))
	for i, ttl := range ub.MsgUBlock().UtreexoData.TxoTTLs {
		remember[i] = ttl < uview.accumulator.Lookahead
	}

	leaves := BlockToAddLeaves(ub.Block(), remember, outskip, ub.MsgUBlock().UtreexoData.Height)

	err = uview.accumulator.Modify(leaves, ub.MsgUBlock().UtreexoData.AccProof.Targets)
	if err != nil {
		panic(err)
		//return err
	}

	uview.bestHash = *ub.Hash()

	return nil
}

// BlockToAdds turns all the new utxos in a msgblock into leafTxos
// uses remember slice up to number of txos, but doesn't check that it's the
// right length.  Similar with skiplist, doesn't check it.
func BlockToAddLeaves(blk *btcutil.Block,
	remember []bool, skiplist []uint32,
	height int32) (leaves []accumulator.Leaf) {

	var txonum uint32
	// bh := bl.Blockhash
	for coinbaseif0, tx := range blk.Transactions() {
		// cache txid aka txhash
		for i, out := range tx.MsgTx().TxOut {
			// Skip all the OP_RETURNs
			if isUnspendable(out) {
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
			l.TxHash = btcacc.Hash(*tx.Hash())
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
		//entries:     make(map[chainhash.Hash]*btcacc.LeafData),
		accumulator: accumulator.Pollard{},
	}
}
