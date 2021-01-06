// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/txscript"
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
	forest *accumulator.Forest
}

func NewUtreexoBridgeState() *UtreexoBridgeState {
	// Default to ram for now
	return &UtreexoBridgeState{
		forest: accumulator.NewForest(nil, false, "", 0),
	}
}

func RestoreUtreexoBridgeState(utreexoBSPath string) (*UtreexoBridgeState, error) {
	miscPath := filepath.Join(utreexoBSPath, "miscforestfile.dat")
	miscFile, err := os.Open(miscPath)
	if err != nil {
		return nil, err
	}
	forestPath := filepath.Join(utreexoBSPath, "forestdata.dat")
	fFile, err := os.Open(forestPath)
	if err != nil {
		return nil, err
	}

	f, err := accumulator.RestoreForest(miscFile, fFile, true, false, "", 0)
	if err != nil {
		return nil, err
	}
	return &UtreexoBridgeState{forest: f}, nil
}

func (b *BlockChain) WriteUtreexoBridgeState(utreexoBSPath string) error {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	// Tells connectBlock to not update the stateSnapshot
	b.utreexoQuit = true

	// Check and make directory if it doesn't exist
	if _, err := os.Stat(utreexoBSPath); os.IsNotExist(err) {
		os.MkdirAll(utreexoBSPath, 0700)
	}
	miscPath := filepath.Join(utreexoBSPath, "miscforestfile.dat")
	miscFile, err := os.OpenFile(miscPath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = b.UtreexoBS.forest.WriteMiscData(miscFile)
	if err != nil {
		return err
	}

	forestPath := filepath.Join(utreexoBSPath, "forestdata.dat")
	fFile, err := os.OpenFile(forestPath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	err = b.UtreexoBS.forest.WriteForestToDisk(fFile, true, false)
	if err != nil {
		return err
	}

	return nil
}

func (b *BlockChain) UpdateUtreexoBS(block *btcutil.Block, stxos []SpentTxOut) (*btcacc.UData, error) {
	if block.Height() == 0 {
		return nil, nil
	}
	inskip, outskip := DedupeBlock(block)
	dels, err := blockToDelLeaves(stxos, block, inskip)
	if err != nil {
		return nil, err
	}

	adds := blockToAddLeaves(block, nil, outskip)

	ud, err := btcacc.GenUData(dels, b.UtreexoBS.forest, block.Height())
	if err != nil {
		return nil, err
	}

	// TODO don't ignore undoblock
	_, err = b.UtreexoBS.forest.Modify(adds, ud.AccProof.Targets)
	if err != nil {
		return nil, err
	}

	return &ud, nil
}

func blockToDelLeaves(stxos []SpentTxOut, block *btcutil.Block, inskip []uint32) (delLeaves []btcacc.LeafData, err error) {
	var blockInIdx uint32
	for idx, tx := range block.Transactions() {
		if idx == 0 {
			blockInIdx++ // coinbase always has 1 input
			continue
		}
		idx--

		for _, txIn := range tx.MsgTx().TxIn {
			// Skip txos on the skip list
			if len(inskip) > 0 && inskip[0] == blockInIdx {
				inskip = inskip[1:]
				blockInIdx++
				continue
			}

			var leaf = btcacc.LeafData{
				// TODO add blockhash in. Left out for compatibility with utreexo master branch
				//BlockHash: *block.Hash(),
				// TODO change this to chainhash.Hash
				TxHash: btcacc.Hash(txIn.PreviousOutPoint.Hash),
				Index:  uint32(txIn.PreviousOutPoint.Index),
				// NOTE blockInIdx is needed for determining skips. So you
				// would really need to variables but you can do this -1
				// since coinbase tx doesn't have an stxo
				Height:   stxos[blockInIdx-1].Height,
				Coinbase: stxos[blockInIdx-1].IsCoinBase,
				Amt:      stxos[blockInIdx-1].Amount,
				PkScript: stxos[blockInIdx-1].PkScript,
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
func blockToAddLeaves(block *btcutil.Block, remember []bool, outskip []uint32) (leaves []accumulator.Leaf) {
	var txonum uint32
	for coinbase, tx := range block.Transactions() {
		for outIdx, txOut := range tx.MsgTx().TxOut {
			// Skip all the OP_RETURNs
			if txscript.IsUnspendable(txOut.PkScript) {
				txonum++
				continue
			}
			// Skip txos on the skip list
			if len(outskip) > 0 && outskip[0] == txonum {
				outskip = outskip[1:]
				txonum++
				continue
			}

			var leaf = btcacc.LeafData{
				// TODO add blockhash in. Left out for compatibility with utreexo master branch
				//BlockHash: *block.Hash(),
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
