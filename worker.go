// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Copyright (c) 2020-2021 The Utreexo developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/chaincfg"
)

const (
	MagicBytes   uint32 = 0xd9b4befa
	NewNodeReady uint32 = 0xfffffffa
	HeaderSize   uint32 = 20
	CommandSize  uint32 = 12
)

type processedURootHint struct {
	Validated       bool
	URootHintHeight int32
}

type workerChan struct {
	num         int32
	getWorkChan chan int32
}

type remoteWorkerMsgHeader struct {
	magic   uint32 // 4 bytes
	command string // 12 bytes
	length  uint32 // 4 bytes
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
		err = fmt.Errorf("readMsgHeader read wrong magic bytes of "+"%v",
			rwhdr.magic)
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

//func writeWorkerMsg(writer io.Writer, cmd string) {
//	var command [CommandSize]byte
//	copy(command[:], []byte(cmd))
//
//	// Create header for the message.
//	hdr := remoteWorkerMsgHeader{}
//	hdr.magic = MagicBytes
//	hdr.command = cmd
//
//	hw := bytes.NewBuffer(make([]byte, 0, HeaderSize))
//	buf := make([]byte, 4)
//
//	binary.BigEndian.PutUint32(buf, hdr.magic)
//	hw.Write(buf)
//	hw.Write(command[:])
//
//	serialized := make([]byte, 4)
//	binary.BigEndian.PutUint32(serialized, uint32(rootHintHeight))
//	hdr.length = uint32(len(serialized))
//
//	binary.BigEndian.PutUint32(buf, hdr.length)
//	hw.Write(buf)
//
//	hw.Write(serialized)
//
//	conn.Write(hw.Bytes())
//}

// MainNode is the main node for doing the initial block download. MainNode hands
// off work to other nodes if they are available.
type MainNode struct {
	started  int32
	shutdown int32
	wg       sync.WaitGroup
	quit     chan struct{}
	refresh  chan struct{}

	// numWorkers is the amount of workers that are available to perform
	// the initial block download.
	numWorkers int32

	// all the available workers
	workers []*LocalWorker

	// The UtreexoRootHints that this MainNode must verify to complete
	// the initial block download.
	UtreexoRootHints []int32
	//UtreexoRootHints []chaincfg.UtreexoRootHint

	// Below are used to communicate with the workers.
	rangeProcessed chan *processedURootHint
	pushWorkChan   chan int32
}

// initializes the UtreexoRootHintsToVerify
func initUtreexoRootHintsToVerify(chainParams *chaincfg.Params) []int32 {
	// init capacity based on the length of the hardcoded root hints.
	rootHints := make([]int32, 0,
		len(chainParams.UtreexoRootHints))

	for _, rootHint := range chainParams.UtreexoRootHints {
		rootHints = append(rootHints, rootHint.Height)
	}

	return rootHints
}

// initMainNode initializes a new MainNode
func initMainNode(chainParams *chaincfg.Params, numWorkers int32) (*MainNode, error) {
	mn := MainNode{
		quit:       make(chan struct{}),
		refresh:    make(chan struct{}),
		numWorkers: numWorkers,
	}
	mn.UtreexoRootHints = initUtreexoRootHintsToVerify(chainParams)
	mn.pushWorkChan = make(chan int32)
	mn.rangeProcessed = make(chan *processedURootHint, len(mn.UtreexoRootHints))

	return &mn, nil
}

func (mn *MainNode) Start() {
	// Already started?
	if atomic.AddInt32(&mn.started, 1) != 1 {
		return
	}

	btcdLog.Trace("Starting utreexo main node. Verifying %d roots",
		len(mn.UtreexoRootHints))
	btcdLog.Infof("Starting utreexo main node. Verifying %d roots",
		len(mn.UtreexoRootHints))
	mn.wg.Add(1)
	go mn.workHandler()
}

func (mn *MainNode) Stop() {
	if atomic.AddInt32(&mn.shutdown, 1) != 1 {
		btcdLog.Warnf("Main node is already in the process of " +
			"shutting down")
		return
	}

	btcdLog.Infof("Main node shutting down")
	close(mn.quit)
	mn.wg.Wait()
}

func (mn *MainNode) listenForResults() {
	// TODO listen for result over network
	hi := processedURootHint{}
	mn.rangeProcessed <- &hi
}

func (mn *MainNode) listenForRemoteWorkers() {
	var workerCount int
	listenAdr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:5555")
	if err != nil {
		btcdLog.Warnf("Couldn't resolve TCP addr err: %s", err)
	}

	listener, err := net.ListenTCP("tcp", listenAdr)
	if err != nil {
		btcdLog.Warnf("Couldn't open TCP listener at %v, err: %s",
			listenAdr, err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			btcdLog.Warnf("Couldn't accept remote connection err: %s", err)
			continue
		}

		go mn.remoteWorkerHandler(conn)
		workerCount++
	}
}

// remoteWorkerHandler is a function that listens for remote workers and writes
// a Utreexo root hint to be validated. This function behaves as a "worker" in that
// it'll listen to the mn.pushWorkChan/mn.rangeProcessed channels and take/push
// to those channels.
//
// This function MUST be ran as a goroutine
func (mn *MainNode) remoteWorkerHandler(conn net.Conn) {
	rootInProcess := make(map[int32]struct{})
out:
	for {
		// Listen to workers
		header, err := readWorkerMsgHeader(conn)
		if err != nil {
			if err == io.EOF {
				btcdLog.Infof("remoteWorkerHandler read EOF while reading header. Disconnecting remote worker")
				break out
			}
			btcdLog.Errorf("remoteWorkerHandler errored while reading header. err: %s", err)
			panic(err)
		}

		// Read payload.
		payload := make([]byte, header.length)
		_, err = io.ReadFull(conn, payload)
		if err != nil {
			if err == io.EOF {
				btcdLog.Infof("remoteWorkerHandler read EOF while reading payload. Disconnecting remote worker")
				break out
			}
			btcdLog.Errorf("remoteWorkerHandler errored while reading payload. err: %s", err)
			panic(err)
		}

		switch header.command {
		case "GetWork":
			select {
			case rootHintHeight, ok := <-mn.pushWorkChan:
				// There will never be a rootHintHeight at 0
				if rootHintHeight == 0 {
					break out
				}
				if ok {
					cmd := "Work"
					var command [CommandSize]byte
					copy(command[:], []byte(cmd))

					// Create header for the message.
					hdr := remoteWorkerMsgHeader{}
					hdr.magic = MagicBytes
					hdr.command = cmd

					hw := bytes.NewBuffer(make([]byte, 0, HeaderSize))
					buf := make([]byte, 4)

					binary.BigEndian.PutUint32(buf, hdr.magic)
					hw.Write(buf)
					hw.Write(command[:])

					serialized := make([]byte, 4)
					binary.BigEndian.PutUint32(serialized, uint32(rootHintHeight))
					hdr.length = uint32(len(serialized))

					binary.BigEndian.PutUint32(buf, hdr.length)
					hw.Write(buf)

					hw.Write(serialized)

					conn.Write(hw.Bytes())
					rootInProcess[rootHintHeight] = struct{}{}
				} else {
					break out
				}
			case <-mn.quit:
				break out
			}
		case "Results":
			verification := payload[:1]
			var valid bool
			if bytes.Equal(verification, []byte{0x01}) {
				valid = true
			}

			height := binary.BigEndian.Uint32(payload[1:])
			mn.rangeProcessed <- &processedURootHint{
				Validated:       valid,
				URootHintHeight: int32(height),
			}
			delete(rootInProcess, int32(height))
		default:
			btcdLog.Errorf("remoteWorkerHandler got an unknown message command of %s from remote worker", header.command)
		}

	}

	if len(rootInProcess) > 0 {
		for rootHeight, _ := range rootInProcess {
			mn.UtreexoRootHints = append(mn.UtreexoRootHints, rootHeight)
		}
		mn.refresh <- struct{}{}
	}

	err := conn.Close()
	if err != nil {
		btcdLog.Errorf("remoteWorkerHandler connection close err: %s", err)
	}
}

// workHandler is the main workhorse for managing all the workers for the main node.
// workHandler is responsible for two things:
// 1. pushing Utreexo root hints to be validated
// 2. listening to the workers to listen to their validation results
// When all the UtreexoRootHints hardcoded to the binary is all validated, workHandler
// will exit and close/send done messages to all the workers.
func (mn *MainNode) workHandler() {
	mn.workers = make([]*LocalWorker, 0, mn.numWorkers)
	// Start all the workers
	for i := int32(0); i < mn.numWorkers; i++ {
		nw := NewLocalWorker(mn.pushWorkChan, mn.rangeProcessed, i)
		mn.workers = append(mn.workers, nw)
		nw.Start()
	}

	go mn.listenForRemoteWorkers()

	// Queue all the rootHints to be validated
	allRoots := len(mn.UtreexoRootHints)
	//currentRoot := 0
	processedRoots := 0

out:
	for processedRoots < allRoots {
		// Only send items while there are still items that need to
		// be processed.  The select statement will never select a nil
		// channel.
		var validateChan chan int32
		var uRootHintHeight int32
		if len(mn.UtreexoRootHints) > 0 { // < allRoots {
			validateChan = mn.pushWorkChan

			// grab from the queue
			uRootHintHeight = mn.UtreexoRootHints[len(mn.UtreexoRootHints)-1]
		}
		select {
		case validateChan <- uRootHintHeight:
			// pop from the queue
			mn.UtreexoRootHints = mn.UtreexoRootHints[:len(mn.UtreexoRootHints)-1]
			btcdLog.Infof("Queuing root at height %v", uRootHintHeight)
			//currentRoot++
		case processed := <-mn.rangeProcessed:
			btcdLog.Infof("Processed root at height:%v", processed.URootHintHeight)
			processedRoots++
			//uRootHintHeight = mn.UtreexoRootHints[currentRoot].Height
			if !processed.Validated {
				// If a root is wrong, panic. The binary is incorrect
				// and there's no way of recovering from this.
				str := fmt.Sprintf("Root at height %d is invalid. "+
					"The UtreexoRootHint in this code is incorrect",
					processed.URootHintHeight)
				panic(str)
			}
		// reset if we have rootHints that are queued up again
		case <-mn.refresh:
			break
		case <-mn.quit:
			break out
		}
	}
	close(mn.pushWorkChan)
	btcdLog.Infof("Done verifying all roots")

	// Stop all the workers
	for _, worker := range mn.workers {
		(*worker).Stop()
		(*worker).WaitForShutdown()
	}

	mn.wg.Done()
	btcdLog.Trace("work handler done")
	btcdLog.Infof("Main node work handler done")
}

// Worker is a node that takes in a height of a Utreexo root hint to verify and splits out
// the results of the verification. A Worker can be either local or remote.
// A Worker is in itself, a completely independent utreexo full node. It has a
// fully working server and will connect out to peers to download blocks. When it
// finishes verifying the UtreexoRootHint, it sends a message back to the main
// node that the UtreexoRootHint was verified.
type Worker interface {
	GetWork()
	PushResults(*processedURootHint)
}

type RemoteWorker struct {
	num       int8
	started   int32
	shutdown  int32
	verifying int32
	wg        sync.WaitGroup
	quit      chan struct{}

	// server is the underlying btcd server.
	server *server

	// Below are used to communicate with the main node.
	coordCon       net.Conn
	workChan       chan int32
	getWorkChan    chan int32
	rangeProcessed chan *processedURootHint

	// Below are used to listen for the worker's server to finish verifying the
	// rootHint.
	valChan           chan bool
	inProcessRootHint *chaincfg.UtreexoRootHint
}

func NewRemoteWorker(num int8) *RemoteWorker {
	rwrk := RemoteWorker{
		num:         num,
		quit:        make(chan struct{}),
		getWorkChan: make(chan int32, 1),
		workChan:    make(chan int32, 1),
		valChan:     make(chan bool, 1),
	}
	return &rwrk
}

func (rwrk *RemoteWorker) GetWork() {
	// If we have this channel, we can have a blocking read
	// while also listening for the quit signal
	go func() {
		cmd := "GetWork"
		var command [CommandSize]byte
		copy(command[:], []byte(cmd))

		// Create header for the message.
		hdr := remoteWorkerMsgHeader{}
		hdr.magic = MagicBytes
		hdr.command = cmd

		hw := bytes.NewBuffer(make([]byte, 0, HeaderSize))
		buf := make([]byte, 4)

		binary.BigEndian.PutUint32(buf, hdr.magic)
		hw.Write(buf)
		hw.Write(command[:])

		binary.BigEndian.PutUint32(buf, hdr.length)
		hw.Write(buf)

		fmt.Println("WRITE GETWORK")
		// Tell the main node we're ready
		rwrk.coordCon.Write(hw.Bytes())
		//height := int32(binary.BigEndian.Uint32(buf))
		//workChan <- height
	}()

	select {
	case height := <-rwrk.workChan:
		rwrk.getWorkChan <- height
		break
	case <-rwrk.quit:
		break
	}
}

func (rwrk *RemoteWorker) PushResults(p *processedURootHint) {
	cmd := "Results"
	var command [CommandSize]byte
	copy(command[:], []byte(cmd))

	// Create header for the message.
	hdr := remoteWorkerMsgHeader{}
	hdr.magic = MagicBytes
	hdr.command = cmd

	var bw bytes.Buffer
	if p.Validated {
		//rwrk.coordCon.Write([]byte{0x01})
		bw.Write([]byte{0x01})
	} else {
		//rwrk.coordCon.Write([]byte{0x00})
		bw.Write([]byte{0x00})
	}

	//_ = binary.Write(rwrk.coordCon, binary.BigEndian, p.URootHintHeight)
	_ = binary.Write(&bw, binary.BigEndian, p.URootHintHeight)
	payload := bw.Bytes()
	hdr.length = uint32(len(payload))

	hw := bytes.NewBuffer(make([]byte, 0, HeaderSize))
	buf := make([]byte, 4)

	binary.BigEndian.PutUint32(buf, hdr.magic)
	hw.Write(buf)
	hw.Write(command[:])

	binary.BigEndian.PutUint32(buf, hdr.length)
	hw.Write(buf)

	rwrk.coordCon.Write(hw.Bytes())
	rwrk.coordCon.Write(payload)
}

//func (rwrk *RemoteWorker) pushDone() {
//	cmd := "Done"
//	var command [CommandSize]byte
//	copy(command[:], []byte(cmd))
//
//	// Create header for the message.
//	hdr := remoteWorkerMsgHeader{}
//	hdr.magic = MagicBytes
//	hdr.command = cmd
//
//	hw := bytes.NewBuffer(make([]byte, 0, HeaderSize))
//	buf := make([]byte, 4)
//
//	binary.BigEndian.PutUint32(buf, hdr.magic)
//	hw.Write(buf)
//	hw.Write(command[:])
//
//	binary.BigEndian.PutUint32(buf, hdr.length)
//	hw.Write(buf)
//
//	fmt.Println("WRITE DONE")
//	// Tell the main node we're done
//	rwrk.coordCon.Write(hw.Bytes())
//}

func (rwrk *RemoteWorker) Start() {
	// Already started?
	if atomic.AddInt32(&rwrk.started, 1) != 1 {
		return
	}

	btcdLog.Trace("Starting utreexo remote worker")
	btcdLog.Infof("Starting utreexo remote worker")

	dialAddr, err := net.ResolveTCPAddr("tcp", cfg.MainNodeIP+":5555")
	if err != nil {
		btcdLog.Errorf("Couldn't resolve TCP addr err: %s", err)
	}

	rwrk.coordCon, err = net.DialTCP("tcp", nil, dialAddr)
	if err != nil {
		btcdLog.Warnf("Couldn't connect to coordinator at %v, err: %s",
			dialAddr, err)
	}

	rwrk.wg.Add(1)
	go rwrk.workHandler()
}

func (rwrk *RemoteWorker) Stop() {
	if atomic.AddInt32(&rwrk.shutdown, 1) != 1 {
		btcdLog.Warnf("Remote worker is already in the process of " +
			"shutting down")
		return
	}
	btcdLog.Infof("remote worker shutting down")
	close(rwrk.quit)
	rwrk.wg.Wait()
	return
}

func (rwrk *RemoteWorker) WaitForShutdown() {
	rwrk.wg.Wait()
	return
}

func (rwrk *RemoteWorker) listen() {
funcout:
	for {
		rwhdr, err := readWorkerMsgHeader(rwrk.coordCon)
		if err != nil {
			if err == io.EOF {
				btcdLog.Infof("workHandler read EOF while reading header. Disconnecting mainnode")
				rwrk.quit <- struct{}{}
				break funcout
			}
			btcdLog.Errorf("workHandler errored while reading header. err: %s", err)
			continue
		}

		switch rwhdr.command {
		case "Work":
			heightBuf := make([]byte, rwhdr.length)
			_, err := io.ReadFull(rwrk.coordCon, heightBuf)
			if err != nil {
				if err == io.EOF {
					btcdLog.Infof("workHandler read EOF while reading Work msg. Disconnecting mainnode")
					rwrk.quit <- struct{}{}
					break funcout
				}
				btcdLog.Errorf("workHandler errored while reading Work msg. err: %s", err)
				panic(err)
			}
			height := binary.BigEndian.Uint32(heightBuf[:])
			rwrk.workChan <- int32(height)
		case "Done":
			rwrk.quit <- struct{}{}
		default:
			btcdLog.Errorf("workHandler got an unknown message command of %s from the mainnode", rwhdr.command)

		}
	}
}

// workHandler is the main workhorse for recieving utreexo roots to verify. workHandler
// must be called as a goroutine.
func (rwrk *RemoteWorker) workHandler() {
	// listen for messages from the coordinator
	go rwrk.listen()
out:
	for {
		// If we're in the process of verifying something, block here and don't
		// queue up for another rootHint
		if rwrk.inProcessRootHint != nil {
			select {
			case verified := <-rwrk.valChan:
				fmt.Println("verified", verified,
					rwrk.inProcessRootHint.Height)
				// TODO push here
				rwrk.PushResults(
					&processedURootHint{
						Validated:       verified,
						URootHintHeight: rwrk.inProcessRootHint.Height,
					},
				)

				// shutdown server to free the memory
				rwrk.server.Stop()
				rwrk.server.WaitForShutdown()
				rwrk.server = nil

				// set inProcessRootHint to nil since we're not
				// verifying anything anymore
				rwrk.inProcessRootHint = nil
			case <-rwrk.quit:
				break out
			}
		}

		// We're not verifying anything at the moment so queue up for a rootHint
		btcdLog.Infof("remote worker num %v queuing for work", rwrk.num)

		rwrk.GetWork()
		// TODO receive work here
		select {
		case uRootHintToVerifyHeight, ok := <-rwrk.getWorkChan:
			if ok {
				btcdLog.Infof("Work received for rootHint height:%v for worker:%v",
					uRootHintToVerifyHeight, rwrk.num)

				// if the channel is still open, go through the verification steps
				interrupt := make(chan struct{}) // something for newServer func compat

				newServer, err := newServer(cfg.Listeners, cfg.AgentBlacklist,
					cfg.AgentWhitelist, nil, activeNetParams.Params, interrupt)
				if err != nil {
					btcdLog.Errorf("Unable to create server for the worker: %v", err)
					return
				}

				rwrk.server = newServer

				// Grab the rootHint for the provided height. If nil, then panic since the
				// worker's rootHints are different from that of the main node
				rwrk.inProcessRootHint = rwrk.server.chain.FindRootHintByHeight(uRootHintToVerifyHeight)
				if rwrk.inProcessRootHint == nil {
					err = fmt.Errorf("Unable to find the Utreexo Root Hint for height: %v. Panicking...", uRootHintToVerifyHeight)
					btcdLog.Errorf("%s", err)
					panic(err)
				}

				rwrk.server.StartUtreexoRootHintVerify(
					rwrk.inProcessRootHint, rwrk.valChan)
			} else {
				break out
			}
		case <-rwrk.quit:
			break out
		}
	}

	if rwrk.server != nil {
		rwrk.server.Stop()
		rwrk.server.WaitForShutdown()
	}

	rwrk.wg.Done()
	btcdLog.Trace("work handler done")
	btcdLog.Infof("work handler done")
}

type LocalWorker struct {
	num       int32
	started   int32
	shutdown  int32
	verifying int32
	wg        sync.WaitGroup
	quit      chan struct{}

	// server is the underlying btcd server.
	server *server

	// Below are used to communicate with the main node.
	coordChan      chan int32
	getWorkChan    chan int32
	rangeProcessed chan *processedURootHint

	// Below are used to listen for the worker's server to finish verifying the
	// rootHint.
	valChan           chan bool
	inProcessRootHint *chaincfg.UtreexoRootHint
}

func (wrk *LocalWorker) GetWork() {
	height, ok := <-wrk.coordChan
	if ok {
		wrk.getWorkChan <- height
	}
}

func (wrk *LocalWorker) PushResults(result *processedURootHint) {
	wrk.rangeProcessed <- result
}

func NewLocalWorker(coordChan chan int32, rangeProcessed chan *processedURootHint, num int32) *LocalWorker {
	wrk := LocalWorker{
		num:            num,
		quit:           make(chan struct{}),
		rangeProcessed: rangeProcessed,
		coordChan:      coordChan,
		getWorkChan:    make(chan int32, 1),
		valChan:        make(chan bool, 1),
	}

	return &wrk
}

func (wrk *LocalWorker) Start() {
	// Already started?
	if atomic.AddInt32(&wrk.started, 1) != 1 {
		return
	}

	btcdLog.Trace("Starting utreexo worker")
	btcdLog.Infof("Starting utreexo worker")
	wrk.wg.Add(1)
	go wrk.workHandler()
}

func (wrk *LocalWorker) Stop() {
	if atomic.AddInt32(&wrk.shutdown, 1) != 1 {
		btcdLog.Warnf("Worker is already in the process of " +
			"shutting down")
		return
	}
	btcdLog.Infof("worker shutting down")
	close(wrk.quit)
	wrk.wg.Wait()
}

// WaitForShutdown blocks until the main listener and peer handlers are stopped.
func (wrk *LocalWorker) WaitForShutdown() {
	wrk.wg.Wait()
}

// isVerifying returns if the worker is currently busy verifying a utreexo
// root hint.
func (wrk *LocalWorker) isVerifying() bool {
	return atomic.AddInt32(&wrk.verifying, 1) != 1
}

// workHandler is the main workhorse for recieving utreexo roots to verify. workHandler
// must be called as a goroutine.
func (wrk *LocalWorker) workHandler() {
out:
	for {
		// If we're in the process of verifying something, block here and don't
		// queue up for another rootHint
		if wrk.inProcessRootHint != nil {
			select {
			case verified := <-wrk.valChan:
				// TODO push here
				wrk.PushResults(
					&processedURootHint{
						Validated:       verified,
						URootHintHeight: wrk.inProcessRootHint.Height,
					},
				)
				//wrk.rangeProcessed <- &processedURootHint{
				//	Validated: verified,
				//	URootHint: wrk.inProcessRootHint,
				//}

				// shutdown server to free the memory
				wrk.server.Stop()
				wrk.server.WaitForShutdown()
				wrk.server = nil

				// set inProcessRootHint to nil since we're not
				// verifying anything anymore
				wrk.inProcessRootHint = nil
			case <-wrk.quit:
				break out
			}
		}

		// We're not verifying anything at the moment so queue up for a rootHint
		btcdLog.Infof("worker num %v queuing for work", wrk.num)

		// TODO ugly. Since we just introduce another channel for the worker
		// just to share an interface with the RemoteWorker.
		// Whatevs
		wrk.GetWork()
		// TODO receive work here
		select {
		case uRootHintToVerifyHeight, ok := <-wrk.getWorkChan:
			if ok {
				btcdLog.Infof("Work received for rootHint height:%v for worker:%v",
					uRootHintToVerifyHeight, wrk.num)

				// if the channel is still open, go through the verification steps
				interrupt := make(chan struct{}) // something for newServer func compat

				newServer, err := newServer(cfg.Listeners, cfg.AgentBlacklist,
					cfg.AgentWhitelist, nil, activeNetParams.Params, interrupt)
				if err != nil {
					fmt.Println(err)
					btcdLog.Errorf("Unable to create server for the worker: %v", err)
					return
				}

				wrk.server = newServer

				// Grab the rootHint for the provided height. If nil, then panic since the
				// worker's rootHints are different from that of the main node
				wrk.inProcessRootHint = wrk.server.chain.FindRootHintByHeight(uRootHintToVerifyHeight)
				if wrk.inProcessRootHint == nil {
					err = fmt.Errorf("Unable to find the Utreexo Root Hint for height: %v. Panicking...", uRootHintToVerifyHeight)
					btcdLog.Errorf("%s", err)
					panic(err)
				}

				wrk.server.StartUtreexoRootHintVerify(
					wrk.inProcessRootHint, wrk.valChan)
			} else {
				break out
			}
		case <-wrk.quit:
			break out
		}
	}

	if wrk.server != nil {
		wrk.server.Stop()
		wrk.server.WaitForShutdown()
	}

	wrk.wg.Done()
	btcdLog.Trace("work handler done")
	btcdLog.Infof("work handler done")
}
