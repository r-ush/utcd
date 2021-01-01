// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/mit-dci/utreexo/accumulator"
	"github.com/mit-dci/utreexo/btcacc"
)

const (
	// lookahead is the max amount that the utreexo bridgenode should
	// generate time-to-live values for an individual txo
	// During the initial block download, a utreexo bridgenode will
	// hold this many blocks in memory to update the ttl values
	lookahead = 1000
)

type UtreexoBridgeState struct {
	forest accumulator.Forest
}

// the data from a block about txo creation and deletion for TTL calculation
type ttlRawBlock struct {
	blockHeight       int32            // height of this block in the chain
	newTxos           []*wire.OutPoint // serialized outpoint for every output
	spentTxos         []*wire.OutPoint // serialized outpoint for every input
	spentStartHeights []int32          // tied 1:1 to spentTxos
}

//type proofQueue struct {
//	height   int
//	accProof *accumulator.BatchProof
//}

// UpdateTTL looks back at the previous blocks and updates
func UpdateTTL(block *btcutil.Block) error {
	inskip, outskip := DedupeBlock(block)

	adds := blockToAddLeaves(block, nil, outskip)
	dels, err := blockToDelLeaves(nil, block, inskip)
	if err != nil {
		return err
	}

	ud, err := btcacc.GenUData(dels, nil, block.Height())
	if err != nil {
		return err
	}

	fmt.Println(adds, ud)

	return nil
}

// storeUData stores all the udata for the blocks that have passed the lookahead
// since creation.
func storeUData() {
}

func blockToDelLeaves(chain *BlockChain, block *btcutil.Block, skiplist []uint32) (delLeaves []btcacc.LeafData, err error) {
	spends, err := chain.FetchSpendJournal(block)
	if err != nil {
		return nil, err
	}

	var blockInIdx uint32
	for idx, tx := range block.Transactions() {
		if idx == 0 {
			blockInIdx++ // coinbase always has 1 output
			continue
		}
		idx--

		for _, txIn := range tx.MsgTx().TxIn {
			// Skip txos on the skip list
			if len(skiplist) > 0 && skiplist[0] == blockInIdx {
				skiplist = skiplist[1:]
				blockInIdx++
				continue
			}

			var leaf = btcacc.LeafData{
				BlockHash: *block.Hash(),
				// TODO change this to chainhash.Hash
				TxHash:   btcacc.Hash(txIn.PreviousOutPoint.Hash),
				Index:    uint32(txIn.PreviousOutPoint.Index),
				Height:   spends[idx].Height,
				Coinbase: spends[idx].IsCoinBase,
				Amt:      spends[idx].Amount,
				PkScript: spends[idx].PkScript,
			}

			delLeaves = append(delLeaves, leaf)
			blockInIdx++
		}
	}

	return
}

// blockToAdds turns all the new utxos in a msgblock into leafTxos
// uses remember slice up to number of txos, but doesn't check that it's the
// right length.  Similar with skiplist, doesn't check it.
func blockToAddLeaves(block *btcutil.Block, remember []bool, skiplist []uint32) (leaves []accumulator.Leaf) {
	var txonum uint32
	for coinbase, tx := range block.Transactions() {
		for outIdx, txOut := range tx.MsgTx().TxOut {
			// Skip all the OP_RETURNs
			if txscript.IsUnspendable(txOut.PkScript) {
				txonum++
				continue
			}
			// Skip txos on the skip list
			if len(skiplist) > 0 && skiplist[0] == txonum {
				skiplist = skiplist[1:]
				txonum++
				continue
			}

			var leaf = btcacc.LeafData{
				BlockHash: *block.Hash(),
				// TODO change this to chainhash.Hash
				TxHash:   btcacc.Hash(*tx.Hash()),
				Index:    uint32(outIdx),
				Height:   block.Height(),
				Coinbase: coinbase == 0,
				Amt:      txOut.Value,
				PkScript: txOut.PkScript,
			}

			uleaf := accumulator.Leaf{Hash: leaf.LeafHash()}

			if len(remember) > int(txonum) {
				uleaf.Remember = remember[txonum]
			}

			leaves = append(leaves, uleaf)
			txonum++
		}
	}

	return
}

// ParseBlockForDB gets a block and creates a ttlRawBlock to send to the DB worker
func ParseBlockForDB(
	block *btcutil.Block, inskip, outskip []uint32) ttlRawBlock {

	var trb ttlRawBlock
	trb.blockHeight = block.Height()

	var txoInBlock uint32 //, txinInBlock uint32

	// iterate through the transactions in a block
	for _, tx := range block.Transactions() {
		// for all the txouts, get their outpoint & index and throw that into
		// a db batch
		for txoInTx, txo := range tx.MsgTx().TxOut {
			if len(outskip) > 0 && txoInBlock == outskip[0] {
				// skip inputs in the txin skiplist
				// fmt.Printf("skipping output %s:%d\n", txid.String(), txoInTx)
				outskip = outskip[1:]
				txoInBlock++
				continue
			}
			if txscript.IsUnspendable(txo.PkScript) {
				txoInBlock++
				continue
			}

			trb.newTxos = append(trb.newTxos,
				wire.NewOutPoint(tx.Hash(), uint32(txoInTx)))
			txoInBlock++
		}

		// for all the txins, throw that into the work as well; just a bunch of
		// outpoints
		//for txinInTx, in := range tx.MsgTx().TxIn { // bit of a tounge twister
		//	if txInBlock == 0 {
		//		txinInBlock += uint32(len(tx.MsgTx().TxIn))
		//		break // skip coinbase input
		//	}
		//	if len(inskip) > 0 && txinInBlock == inskip[0] {
		//		// skip inputs in the txin skiplist
		//		// fmt.Printf("skipping input %s\n", in.PreviousOutPoint.String())
		//		inskip = inskip[1:]
		//		txinInBlock++
		//		continue
		//	}
		//	// append outpoint to slice
		//	trb.spentTxos = append(trb.spentTxos,
		//		&in.PreviousOutPoint)
		//	// append start height to slice (get from rev data)
		//	trb.spentStartHeights = append(trb.spentStartHeights,
		//		bnr.Rev.Txs[txInBlock-1].TxIn[txinInTx].Height)

		//	txinInBlock++
		//}
	}

	return trb
}

// dedupeBlock marks same block spends
//func dedupeBlock(block *btcutil.Block) (inskip []int, outskip []int) {
//	for coinbase, tx := range block.Transactions() {
//		if coinbase == 0 {
//			continue
//		}
//		for inIdx, txIn := range tx.MsgTx().TxIn {
//			for outIdx, _ := range tx.MsgTx().TxOut {
//				op := wire.OutPoint{Hash: *tx.Hash(), Index: uint32(outIdx)}
//
//				if op == txIn.PreviousOutPoint {
//					fmt.Println("hit")
//					inskip = append(inskip, inIdx)
//					outskip = append(outskip, outIdx)
//				}
//
//			}
//		}
//	}
//
//	return
//}
