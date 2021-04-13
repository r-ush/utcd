// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// maybeAcceptHeader potentially accepts a block header to build the block index
func (b *BlockChain) maybeAcceptHeader(header *wire.BlockHeader, utreexoStartRoot *chaincfg.UtreexoRootHint, flags BehaviorFlags) error {
	// Check if the previous block header exists
	prevHash := &header.PrevBlock
	prevNode := b.index.LookupNode(prevHash)
	if prevNode == nil {
		str := fmt.Sprintf("previous header %s is unknown", prevHash)
		return ruleError(ErrPreviousHeaderUnknown, str)
	}

	// Check sanity. This includes timestamp checking
	err := checkBlockHeaderSanity(header, b.chainParams.PowLimit, b.timeSource, flags)
	if err != nil {
		return err
	}

	// Create a new block node for the block and add it to the node index.
	newNode := newBlockNode(header, prevNode)
	b.index.AddNodeNoDirty(newNode)
	newNode.BuildAncestor()

	// If we're in utreexo root verify mode and is
	// verifying from the genesis, return here
	if utreexoStartRoot == nil {
		return nil
	}

	// If we're in utreexo root verify mode, set the bestChain tip
	//
	// TODO We're hashing twice per header here since there's a
	// hash in checkBlockHeaderSanity
	if header.BlockHash() == *utreexoStartRoot.Hash {
		log.Infof("Setting the starting block to verify at height %v",
			utreexoStartRoot.Height)
		// This node is now the end of the best chain.
		b.bestChain.SetTip(newNode)
	}

	return nil
}

// maybeAcceptHeaderUBlock is used for the utreesxo root verify mode and doesn't save
// any blocks to the disk.
func (b *BlockChain) maybeAcceptHeaderUBlock(ublock *btcutil.UBlock, uView *UtreexoViewpoint, flags BehaviorFlags) (bool, error) {
	// The height of this block is one more than the referenced previous
	// block.
	prevHash := &ublock.Block().MsgBlock().Header.PrevBlock
	prevNode := b.index.LookupNode(prevHash)
	if prevNode == nil {
		str := fmt.Sprintf("previous block %s is unknown", prevHash)
		return false, ruleError(ErrPreviousBlockUnknown, str)
	} else if b.index.NodeStatus(prevNode).KnownInvalid() {
		str := fmt.Sprintf("previous block %s is known to be invalid", prevHash)
		return false, ruleError(ErrInvalidAncestorBlock, str)
	}

	blockHeight := prevNode.height + 1
	ublock.SetHeight(blockHeight)

	// The block must pass all of the validation rules which depend on the
	// position of the block within the block chain.
	err := b.checkBlockContext(ublock.Block(), prevNode, flags)
	if err != nil {
		return false, err
	}

	curNode := b.index.LookupNode(ublock.Hash())

	isMainChain, err := b.connectBestChainParallel(curNode, ublock, uView, flags)
	if err != nil {
		return false, err
	}

	return isMainChain, nil
}

// maybeAcceptBlock potentially accepts a block into the block chain and, if
// accepted, returns whether or not it is on the main chain.  It performs
// several validation checks which depend on its position within the block chain
// before adding it.  The block is expected to have already gone through
// ProcessBlock before calling this function with it.
//
// The flags are also passed to checkBlockContext and connectBestChain.  See
// their documentation for how the flags modify their behavior.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) maybeAcceptBlock(block *btcutil.Block, flags BehaviorFlags) (bool, error) {
	// The height of this block is one more than the referenced previous
	// block.
	prevHash := &block.MsgBlock().Header.PrevBlock
	prevNode := b.index.LookupNode(prevHash)
	if prevNode == nil {
		str := fmt.Sprintf("previous block %s is unknown", prevHash)
		return false, ruleError(ErrPreviousBlockUnknown, str)
	} else if b.index.NodeStatus(prevNode).KnownInvalid() {
		str := fmt.Sprintf("previous block %s is known to be invalid", prevHash)
		return false, ruleError(ErrInvalidAncestorBlock, str)
	}

	blockHeight := prevNode.height + 1
	block.SetHeight(blockHeight)

	// The block must pass all of the validation rules which depend on the
	// position of the block within the block chain.
	err := b.checkBlockContext(block, prevNode, flags)
	if err != nil {
		return false, err
	}

	// Insert the block into the database if it's not already there.  Even
	// though it is possible the block will ultimately fail to connect, it
	// has already passed all proof-of-work and validity tests which means
	// it would be prohibitively expensive for an attacker to fill up the
	// disk with a bunch of blocks that fail to connect.  This is necessary
	// since it allows block download to be decoupled from the much more
	// expensive connection logic.  It also has some other nice properties
	// such as making blocks that never become part of the main chain or
	// blocks that fail to connect available for further analysis.
	err = b.db.Update(func(dbTx database.Tx) error {
		return dbStoreBlock(dbTx, block)
	})
	if err != nil {
		return false, err
	}

	// Create a new block node for the block and add it to the node index. Even
	// if the block ultimately gets connected to the main chain, it starts out
	// on a side chain.
	blockHeader := &block.MsgBlock().Header
	newNode := newBlockNode(blockHeader, prevNode)
	newNode.status = statusDataStored

	b.index.AddNode(newNode)
	newNode.BuildAncestor()
	err = b.index.flushToDB()
	if err != nil {
		return false, err
	}

	// Connect the passed block to the chain while respecting proper chain
	// selection according to the chain with the most proof of work.  This
	// also handles validation of the transaction scripts.
	isMainChain, err := b.connectBestChain(newNode, block, flags)
	if err != nil {
		return false, err
	}

	// Notify the caller that the new block was accepted into the block
	// chain.  The caller would typically want to react by relaying the
	// inventory to other peers.
	b.chainLock.Unlock()
	b.sendNotification(NTBlockAccepted, block)
	b.chainLock.Lock()

	return isMainChain, nil
}

func (b *BlockChain) maybeAcceptUBlock(ublock *btcutil.UBlock, flags BehaviorFlags) (bool, error) {
	// The height of this block is one more than the referenced previous
	// block.
	prevHash := &ublock.Block().MsgBlock().Header.PrevBlock
	prevNode := b.index.LookupNode(prevHash)
	if prevNode == nil {
		str := fmt.Sprintf("previous block %s is unknown", prevHash)
		return false, ruleError(ErrPreviousBlockUnknown, str)
	} else if b.index.NodeStatus(prevNode).KnownInvalid() {
		str := fmt.Sprintf("previous block %s is known to be invalid", prevHash)
		return false, ruleError(ErrInvalidAncestorBlock, str)
	}

	blockHeight := prevNode.height + 1
	ublock.SetHeight(blockHeight)

	// The block must pass all of the validation rules which depend on the
	// position of the block within the block chain.
	err := b.checkBlockContext(ublock.Block(), prevNode, flags)
	if err != nil {
		return false, err
	}

	// Insert the block into the database if it's not already there.  Even
	// though it is possible the block will ultimately fail to connect, it
	// has already passed all proof-of-work and validity tests which means
	// it would be prohibitively expensive for an attacker to fill up the
	// disk with a bunch of blocks that fail to connect.  This is necessary
	// since it allows block download to be decoupled from the much more
	// expensive connection logic.  It also has some other nice properties
	// such as making blocks that never become part of the main chain or
	// blocks that fail to connect available for further analysis.
	//if b.utreexoCSN {
	//	b.memBlocks.StoreBlock(ublock.Block())
	//} else {
	//err = b.db.Update(func(dbTx database.Tx) error {
	//	return dbStoreBlock(dbTx, ublock.Block())
	//})
	//if err != nil {
	//	return false, err
	//}
	//}

	// Create a new block node for the block and add it to the node index. Even
	// if the block ultimately gets connected to the main chain, it starts out
	// on a side chain.
	blockHeader := &ublock.Block().MsgBlock().Header
	newNode := newBlockNode(blockHeader, prevNode)
	newNode.BuildAncestor()
	newNode.status = statusDataStored

	b.index.AddNode(newNode)
	//err = b.index.flushToDB()
	//if err != nil {
	//	return false, err
	//}

	isMainChain, err := b.connectBestChainUBlock(newNode, ublock, flags)
	if err != nil {
		return false, err
	}
	return isMainChain, nil
}
