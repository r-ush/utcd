package wire

import (
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/mit-dci/utreexo/btcacc"
)

type MsgUBlock struct {
	MsgBlock    *MsgBlock
	UtreexoData *btcacc.UData
}

func (ub *MsgUBlock) BlockHash() chainhash.Hash {
	return ub.MsgBlock.BlockHash()
}

func (ub *MsgUBlock) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := ub.MsgBlock.Deserialize(r)
	if err != nil {
		return err
	}
	err = ub.UtreexoData.Deserialize(r)

	return nil
}

func (ub *MsgUBlock) BtcEncode(r io.Writer, pver uint32, enc MessageEncoding) error {
	err := ub.MsgBlock.Serialize(r)
	if err != nil {
		return err
	}
	err = ub.UtreexoData.Serialize(r)

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgUBlock) Command() string {
	return CmdUBlock
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgUBlock) MaxPayloadLength(pver uint32) uint32 {
	// Block header at 80 bytes + transaction count + max transactions
	// which can vary up to the MaxBlockPayload (including the block header
	// and transaction count).
	return MaxBlockPayload
}
