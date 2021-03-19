package blockchain

import (
	"github.com/btcsuite/btcd/chaincfg"
)

// UtreexoRootHints returns the underlying utreexoRootHints.
func (b *BlockChain) UtreexoRootHints() []chaincfg.UtreexoRootHint {
	return b.utreexoRootHints
}

// UtreexoRootHints returns the underlying utreexoRoot being verified.
func (b *BlockChain) UtreexoRootBeingVerified() *chaincfg.UtreexoRootHint {
	return b.utreexoRootToVerify
}

// FindRootHintByHeight returns the rootHint for the given height. If one can't be found,
// nil is returned.
func (b *BlockChain) FindRootHintByHeight(height int32) *chaincfg.UtreexoRootHint {
	rootHint, found := b.utreexoRootHintsByHeight[height]
	if !found {
		return nil
	}
	return rootHint
}

// findNextUtreexoRootHint returns the next Utreexo root hint
func (b *BlockChain) findNextUtreexoRootHint(height int32) *chaincfg.UtreexoRootHint {
	roots := b.UtreexoRootHints()
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

// findPreviousUtreexoRootHint returns the previous Utreexo root hint
func (b *BlockChain) findPreviousUtreexoRootHint(height int32) *chaincfg.UtreexoRootHint {
	roots := b.UtreexoRootHints()
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
