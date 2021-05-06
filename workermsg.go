package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

const (
	CmdWork            = "work"
	CmdGetWork         = "getwork"
	CmdGetStartHeaders = "getsheaders"
	CmdStartHeaders    = "startheaders"
	CmdResult          = "result"
)

type remoteWorkerMsgHeader struct {
	magic   uint32 // 4 bytes
	command string // 12 bytes
	length  uint32 // 4 bytes
}

func (hdr *remoteWorkerMsgHeader) Serialize(w io.Writer) {
	// Write magic
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, hdr.magic)
	w.Write(buf)

	// Write command
	if hdr.command == "" {
		panic("remoteWorkerMsgHeader Serialize command empty")
	}
	var command [CommandSize]byte
	copy(command[:], []byte(hdr.command))
	w.Write(command[:])

	// Write length
	binary.BigEndian.PutUint32(buf, hdr.length)
	w.Write(buf)
}

func readWorkerMsgHeader(reader io.Reader) (*remoteWorkerMsgHeader, error) {
	rwhdr := &remoteWorkerMsgHeader{}

	headerBuf := make([]byte, HeaderSize)
	_, err := io.ReadFull(reader, headerBuf)
	if err != nil {
		return nil, err
	}

	rwhdr.magic = binary.BigEndian.Uint32(headerBuf[:4])
	if rwhdr.magic != MagicBytes {
		err = fmt.Errorf("readMsgHeader read wrong magic bytes of "+
			"%v, when it should have read %v",
			rwhdr.magic, MagicBytes)
		return nil, err
	}

	// Read command.
	commandBuf := make([]byte, CommandSize)
	copy(commandBuf, headerBuf[4:4+12])

	// Strip trailing zeros from command string.
	rwhdr.command = string(bytes.TrimRight(commandBuf, "\x00"))

	rwhdr.length = binary.BigEndian.Uint32(headerBuf[16 : 16+4])

	return rwhdr, nil
}

func WriteWorkerMessage(w io.Writer, msg WorkerMessage) error {
	// Encode the message payload.
	var bw bytes.Buffer
	err := msg.Encode(&bw)
	if err != nil {
		return err
	}

	payload := bw.Bytes()
	lenp := len(payload)

	hdr := remoteWorkerMsgHeader{}
	hdr.magic = MagicBytes

	// Enforce max command size.
	hdr.command = msg.Command()
	if len(hdr.command) > int(CommandSize) {
		err := fmt.Errorf("command [%s] is too long [max %v]",
			hdr.command, CommandSize)
		return err
	}

	hdr.length = uint32(lenp)

	// Write header
	var hw bytes.Buffer
	hdr.Serialize(&hw)
	w.Write(hw.Bytes())

	// Only write the payload if there is one
	if len(payload) > 0 {
		_, err = w.Write(payload)
	}

	return err
}

func ReadWorkerMessage(r io.Reader) (WorkerMessage, []byte, error) {
	hdr, err := readWorkerMsgHeader(r)
	if err != nil {
		return nil, nil, err
	}
	// Create struct of appropriate message type based on the command.
	msg, err := makeEmptyMessage(hdr.command)
	if err != nil {
		return nil, nil, err
	}

	// Read payload.
	payload := make([]byte, hdr.length)
	_, err = io.ReadFull(r, payload)
	if err != nil {
		return nil, nil, err
	}

	pr := bytes.NewBuffer(payload)
	err = msg.Decode(pr)
	if err != nil {
		return nil, nil, err
	}
	return msg, payload, nil
}

// makeEmptyMessage creates a message of the appropriate concrete type based
// on the command.
func makeEmptyMessage(command string) (WorkerMessage, error) {
	var msg WorkerMessage
	switch command {
	case CmdWork:
		msg = &MsgWork{}

	case CmdResult:
		msg = &MsgResult{}

	case CmdGetWork:
		msg = &MsgGetWork{}

	case CmdGetStartHeaders:
		msg = &MsgGetStartHeaders{}

	case CmdStartHeaders:
		msg = &MsgStartHeaders{}

	default:
		return nil, fmt.Errorf("unhandled command [%s]", command)
	}

	return msg, nil
}

// WorkerMessage is the message sent between the remote worker and the coordinator
// to communicate work and result for verifying a utreexo root hint.
type WorkerMessage interface {
	Encode(io.Writer) error
	Decode(io.Reader) error
	Command() string
}

// MsgWork is the message sent from the coordinator node to queue a utreexo root
// hint (and metadata) to the worker.
type MsgWork struct {
	work *work
}

func (msg *MsgWork) Encode(w io.Writer) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(msg.work.uRootHintHeight))
	w.Write(buf)

	return nil
}

func (msg *MsgWork) Decode(r io.Reader) error {
	heightBuf := make([]byte, 4)
	_, err := io.ReadFull(r, heightBuf)
	if err != nil {
		return err
	}

	work := work{}
	work.uRootHintHeight = int32(binary.BigEndian.Uint32(heightBuf[:]))

	msg.work = &work

	return nil
}

func (msg *MsgWork) Command() string {
	return CmdWork
}

// MsgGetWork is the message sent from the worker node to get a work from the coordinator.
type MsgGetWork struct {
	// getWork has no payload
}

func (msg *MsgGetWork) Encode(w io.Writer) error {
	return nil
}

func (msg *MsgGetWork) Decode(r io.Reader) error {
	return nil
}

func (msg *MsgGetWork) Command() string {
	return CmdGetWork
}

// MsgGetStartHeaders is the message sent from the worker node to get all the headers required
// for verifying a utreexo root hint
type MsgGetStartHeaders struct {
	// getStartHeaders has no payload
}

func (msg *MsgGetStartHeaders) Encode(w io.Writer) error {
	return nil
}

func (msg *MsgGetStartHeaders) Decode(r io.Reader) error {
	return nil
}

func (msg *MsgGetStartHeaders) Command() string {
	return CmdGetStartHeaders
}

// MsgStartHeaders is the message sent from the worker node to get all the headers required
// for verifying a utreexo root hint
type MsgStartHeaders struct {
	headers *startHeaders
}

func (msg *MsgStartHeaders) Encode(w io.Writer) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(msg.headers.lastHeight))
	w.Write(buf)

	for _, header := range msg.headers.headers {
		// only writer matters. Other 2 fields don't do anything in the actual
		// encoding function
		err := header.BtcEncode(w, 0, wire.WitnessEncoding)
		if err != nil {
			panic(err)
		}
	}

	for _, hash := range msg.headers.hashes {
		// only writer matters. Other 2 fields don't do anything in the actual
		// encoding function
		_, err := w.Write(hash[:])
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func (msg *MsgStartHeaders) Decode(r io.Reader) error {
	heightBuf := make([]byte, 4)
	_, err := io.ReadFull(r, heightBuf)
	if err != nil {
		return err
	}

	lastHeight := int32(binary.BigEndian.Uint32(heightBuf[:]))

	startH := startHeaders{
		headers:    make([]*wire.BlockHeader, 0, lastHeight),
		hashes:     make([]chainhash.Hash, lastHeight),
		lastHeight: lastHeight,
	}

	for i := int32(0); i < lastHeight; i++ {
		header := wire.BlockHeader{}
		// only reader matters. Other 2 fields don't do anything in the actual
		// encoding function
		err = header.BtcDecode(r, 0, wire.WitnessEncoding)
		if err != nil {
			panic(err)
		}
		startH.headers = append(startH.headers, &header)
	}

	var hash [32]byte
	for i := int32(0); i < lastHeight; i++ {
		// only writer matters. Other 2 fields don't do anything in the actual
		// encoding function
		_, err := r.Read(hash[:])
		if err != nil {
			panic(err)
		}
		hash, err := chainhash.NewHash(hash[:])
		if err != nil {
			panic(err)
		}
		startH.hashes[i] = *hash
	}

	msg.headers = &startH

	return nil
}

func (msg *MsgStartHeaders) Command() string {
	return CmdStartHeaders
}

// MsgWork is the message sent from the worker node to queue a verification result
// to the coordinator.
type MsgResult struct {
	result *result
}

func (msg *MsgResult) Encode(w io.Writer) error {
	w.Write(msg.result.valid[:])

	err := binary.Write(w, binary.BigEndian, msg.result.uRootHintHeight)
	if err != nil {
		return err
	}

	return nil
}

func (msg *MsgResult) Decode(r io.Reader) error {
	resultBuf := make([]byte, 5)
	_, err := r.Read(resultBuf)
	if err != nil {
		return err
	}

	res := result{}
	verification := resultBuf[:1]
	copy(res.valid[:], verification)

	height := binary.BigEndian.Uint32(resultBuf[1:])
	res.uRootHintHeight = int32(height)

	msg.result = &res

	return nil
}

func (msg *MsgResult) Command() string {
	return CmdResult
}
