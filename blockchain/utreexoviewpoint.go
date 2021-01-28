// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"

	"github.com/btcsuite/btcutil"
	"github.com/mit-dci/utreexo/accumulator"
	"github.com/mit-dci/utreexo/btcacc"
)

type UtreexoViewpoint struct {
	accumulator accumulator.Pollard
	//bestHash    chainhash.Hash
}

//// BestHash returns the hash of the best block in the chain the view currently
//// respresents.
//func (uview *UtreexoViewpoint) BestHash() *chainhash.Hash {
//	return &uview.bestHash
//}

//// SetBestHash sets the hash of the best block in the chain the view currently
//// respresents.
//func (uview *UtreexoViewpoint) SetBestHash(hash *chainhash.Hash) {
//	uview.bestHash = *hash
//}

// Modify takes an ublock and adds the utxos and deletes the stxos from the utreexo state
func (uview *UtreexoViewpoint) Modify(ub *btcutil.UBlock) error {
	inskip, outskip := ub.Block().DedupeBlock()

	nl, h := uview.accumulator.ReconstructStats()

	err := ub.ProofSanity(inskip, nl, h)
	if err != nil {
		return err
	}

	err = uview.accumulator.IngestBatchProof(ub.MsgUBlock().UtreexoData.AccProof)
	if err != nil {
		return err
	}

	remember := make([]bool, len(ub.MsgUBlock().UtreexoData.TxoTTLs))
	for i, ttl := range ub.MsgUBlock().UtreexoData.TxoTTLs {
		remember[i] = ttl < uview.accumulator.Lookahead
	}

	leaves := BlockToAddLeaves(ub.Block(), remember, outskip, ub.MsgUBlock().UtreexoData.Height)

	err = uview.accumulator.Modify(leaves, ub.MsgUBlock().UtreexoData.AccProof.Targets)
	if err != nil {
		return err
	}

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

func UBlockToStxos(ublock *btcutil.UBlock, stxos *[]SpentTxOut) error {
	for _, ustxo := range ublock.MsgUBlock().UtreexoData.Stxos {
		stxo := SpentTxOut{
			Amount:     ustxo.Amt,
			PkScript:   ustxo.PkScript,
			Height:     ustxo.Height,
			IsCoinBase: ustxo.Coinbase,
		}
		*stxos = append(*stxos, stxo)
	}

	_, outskip := ublock.Block().DedupeBlock()

	shouldadd := len(outskip)

	var txonum uint32
	var added int
	for coinbaseif0, tx := range ublock.Block().MsgBlock().Transactions {
		for _, txOut := range tx.TxOut {
			// Skip all the OP_RETURNs
			if isUnspendable(txOut) {
				txonum++
				continue
			}
			// Skip txos on the skip list
			if len(outskip) > 0 && outskip[0] == txonum {
				//fmt.Println("ADD:", txonum)
				stxo := SpentTxOut{
					Amount:     txOut.Value,
					PkScript:   txOut.PkScript,
					Height:     ublock.Block().Height(),
					IsCoinBase: coinbaseif0 == 0,
				}
				*stxos = append(*stxos, stxo)
				outskip = outskip[1:]
				txonum++
				added++
				continue
			}
			txonum++
		}
	}
	if added != shouldadd {
		s := fmt.Errorf("should add %v but only added %v. txonum final:%v", shouldadd, added, txonum)
		//fmt.Println(s)
		panic(s)
	}
	return nil
}

func NewUtreexoViewpoint() *UtreexoViewpoint {
	return &UtreexoViewpoint{
		//entries:     make(map[chainhash.Hash]*btcacc.LeafData),
		accumulator: accumulator.Pollard{},
	}
}
