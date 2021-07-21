// Copyright (c) 2021 The utreexo developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcaccumulator

import (
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/mit-dci/utreexo/accumulator"
)

// UData contains data needed to prove the existence and validity of all inputs
// for a Bitcoin block.  With this data, a full node may only keep the utreexo
// roots and still be able to fully validate a block.
type UData struct {
	// Height is the height of the block this UData corresponds to.
	Height int32

	// AccProof is the utreexo accumulator proof for all the inputs.
	AccProof accumulator.BatchProof

	// Stxos are the tx validation data for every input.
	Stxos []LeafData

	// TxoTTLs are the time to live values for all the stxos.
	TxoTTLs []int32
}

// StxosHashes returns the hash of all stxos in this UData.  The hashes returned
// here represent the hash commitments of the stxos.
func (ud *UData) StxoHashes() []chainhash.Hash {
	leafHashes := make([]chainhash.Hash, len(ud.Stxos))
	for i, stxo := range ud.Stxos {
		leafHashes[i] = *stxo.LeafHash()
	}

	return leafHashes
}

// SerializeSize returns the number of bytes it would take to serialize the
// UData.
func (ud *UData) SerializeSize() int {
	// Size of all the leafData.
	var ldSize int
	for _, l := range ud.Stxos {
		ldSize += l.SerializeSize()
	}

	// Size of all the time to live values.
	var txoTTLSize int
	for _, ttl := range ud.TxoTTLs {
		txoTTLSize += wire.VarIntSerializeSize(uint64(ttl))
	}

	// Add on accumulator proof size and the varint serialized height size.
	return txoTTLSize + ldSize + ud.AccProof.SerializeSize() +
		wire.VarIntSerializeSize(uint64(ud.Height))
}

// Serialize encodes the UData to w using the UData serialization format.
func (ud *UData) Serialize(w io.Writer) error {
	err := wire.WriteVarInt(w, 0, uint64(ud.Height))
	if err != nil {
		return err
	}
	err = wire.WriteVarInt(w, 0, uint64(len(ud.TxoTTLs)))
	if err != nil {
		return err
	}
	for _, ttlval := range ud.TxoTTLs {
		err = wire.WriteVarInt(w, 0, uint64(ttlval))
		if err != nil {
			return err
		}
	}

	err = ud.AccProof.Serialize(w)
	if err != nil {
		returnErr := accumulatorError("Serialize", err.Error())
		return returnErr
	}

	// write all the leafdatas
	for _, ld := range ud.Stxos {
		err = ld.Serialize(w)
		if err != nil {
			return err
		}
	}

	return nil
}

// Deserialize encodes the UData to w using the UData serialization format.
func (ud *UData) Deserialize(r io.Reader) error {
	height, err := wire.ReadVarInt(r, 0)
	if err != nil {
		returnErr := accumulatorError("Deserialize height", err.Error())
		return returnErr
	}
	ud.Height = int32(height)

	ttlCount, err := wire.ReadVarInt(r, 0)
	if err != nil {
		returnErr := accumulatorError("Deserialize ttlCount", err.Error())
		return returnErr
	}

	ud.TxoTTLs = make([]int32, ttlCount)
	for i := range ud.TxoTTLs {
		ttl, err := wire.ReadVarInt(r, 0)
		if err != nil {
			returnErr := accumulatorError("Deserialize ttl", err.Error())
			return returnErr
		}

		ud.TxoTTLs[i] = int32(ttl)
	}

	err = ud.AccProof.Deserialize(r)
	if err != nil {
		returnErr := accumulatorError("Deserialize", err.Error())
		return returnErr
	}

	// we've already gotten targets. 1 leafdata per target
	ud.Stxos = make([]LeafData, len(ud.AccProof.Targets))
	for i := range ud.Stxos {
		err = ud.Stxos[i].Deserialize(r)
		if err != nil {
			str := fmt.Sprintf("Height:%d, ttlCount:%d, targetCount:%d, Stxos[%d], err:%s\n",
				ud.Height, ttlCount, len(ud.AccProof.Targets), i, err.Error())
			returnErr := accumulatorError("Deserialize stxos", str)
			return returnErr
		}
	}

	return nil
}

// SerializeSizeCompact returns the number of bytes it would take to serialize the
// UData using the compact UData serialization format.
func (ud *UData) SerializeSizeCompact() int {
	// Size of all the leafData.
	var ldSize int
	for _, l := range ud.Stxos {
		ldSize += l.SerializeSizeCompact()
	}

	// Size of all the time to live values.
	var txoTTLSize int
	for _, ttl := range ud.TxoTTLs {
		txoTTLSize += wire.VarIntSerializeSize(uint64(ttl))
	}

	// Add on accumulator proof size and the varint serialized height size.
	return txoTTLSize + ldSize + ud.AccProof.SerializeSize() +
		wire.VarIntSerializeSize(uint64(ud.Height))
}

// SerializeCompact encodes the UData to w using the compact UData
// serialization format.
func (ud *UData) SerializeCompact(w io.Writer) error {
	err := ud.AccProof.Serialize(w)
	if err != nil {
		returnErr := accumulatorError("SerializeCompact", err.Error())
		return returnErr
	}

	return nil
}

// DeserializeCompact decodes the UData from r using the compact UData
// serialization format.
func (ud *UData) DeserializeCompact(r io.Reader) error {
	err := ud.AccProof.Deserialize(r)
	if err != nil {
		returnErr := accumulatorError("DeserializeCompact", err.Error())
		return returnErr
	}

	return nil
}

// GenerateUData creates a block proof, calling forest.ProveBatch with the leaf indexes
// to get a batched inclusion proof from the accumulator. It then adds on the leaf data,
// to create a block proof which both proves inclusion and gives all utxo data
// needed for transaction verification.
func GenerateUData(txIns []LeafData, forest *accumulator.Forest, blockHeight int32) (
	*UData, error) {

	ud := new(UData)
	ud.Height = blockHeight
	ud.Stxos = txIns

	// make slice of hashes from leafdata
	delHashes := make([]accumulator.Hash, len(ud.Stxos))
	for i, stxo := range ud.Stxos {
		delHashes[i] = accumulator.Hash(*stxo.LeafHash())
	}

	// Generate the utreexo accumulator proof for all the inputs.
	var err error
	ud.AccProof, err = forest.ProveBatch(delHashes)
	if err != nil {
		return nil, err
	}

	if len(ud.AccProof.Targets) != len(txIns) {
		str := fmt.Sprintf("GenerateUData has %d txIns but has proofs for %d txIns",
			len(txIns), len(ud.AccProof.Targets))
		return nil, accumulatorError("GenerateUData", str)
	}

	return ud, nil
}
