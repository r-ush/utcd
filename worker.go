// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Copyright (c) 2020-2021 The Utreexo developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/chaincfg"
)

//// UtreexoRootHintsToVerify is the UtreexoRootHints with metadata to keep
//// track of the verification stage.
//type UtreexoRootHintsToVerify struct {
//	// RootHint is the underlying utreexo root hint.
//	RootHint *chaincfg.UtreexoRootHint
//
//	// Verified sets if the underlying utreexoRootHint is verified or
//	// not.
//	Verified bool
//}
//
//// initializes the UtreexoRootHintsToVerify
//func initUtreexoRootHintsToVerify(chainParams *chaincfg.Params) []*UtreexoRootHintsToVerify {
//	// init capacity based on the length of the hardcoded root hints.
//	rootHints := make([]*UtreexoRootHintsToVerify, 0,
//		len(chainParams.UtreexoRootHints))
//
//	for _, rootHint := range chainParams.UtreexoRootHints {
//		rootHints = append(rootHints, &UtreexoRootHintsToVerify{
//			RootHint: &rootHint,
//			Verified: false,
//		})
//	}
//
//	return rootHints
//}

//// findViablePort keeps incrementing the port until a suitable one is found
//func findViablePort() int32 {
//	return 0
//}

type processedURootHint struct {
	Validated bool
	URootHint *chaincfg.UtreexoRootHint
}

type workerChan struct {
	num         int32
	getWorkChan chan int32
}

// MainNode is the main node for doing the initial block download. MainNode hands
// off work to other nodes if they are available.
type MainNode struct {
	started  int32
	shutdown int32
	wg       sync.WaitGroup
	quit     chan struct{}

	// numWorkers is the amount of workers that are available to perform
	// the initial block download.
	numWorkers int32

	// all the available workers
	workers []*Worker

	// The UtreexoRootHints that this MainNode must verify to complete
	// the initial block download.
	UtreexoRootHints []chaincfg.UtreexoRootHint

	// Below are used to communicate with the workers.
	rangeProcessed chan *processedURootHint
	pushWorkChan   chan int32
}

// initMainNode initializes a new MainNode
func initMainNode(chainParams *chaincfg.Params, numWorkers int32) (*MainNode, error) {
	mn := MainNode{
		quit:       make(chan struct{}),
		numWorkers: numWorkers,
	}
	mn.UtreexoRootHints = chainParams.UtreexoRootHints
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
out:
	for {
		// Wait until a worker is free
		var b []byte
		conn.Read(b)

		select {
		case rootHintHeight := <-mn.pushWorkChan:
			serialized := make([]byte, 4)
			binary.BigEndian.PutUint32(serialized, uint32(rootHintHeight))
			conn.Write(serialized)
		case <-mn.quit:
			break out
		}
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
	mn.workers = make([]*Worker, 0, mn.numWorkers)
	// Start all the workers
	for i := int32(0); i < mn.numWorkers; i++ {
		nw := NewLocalWorker(mn.pushWorkChan, mn.rangeProcessed, i)
		mn.workers = append(mn.workers, &nw)
		nw.Start()
	}

	go mn.listenForRemoteWorkers()

	// Queue all the rootHints to be validated
	allRoots := len(mn.UtreexoRootHints)
	currentRoot := 0
	processedRoots := 0

out:
	for processedRoots < allRoots {
		// Only send items while there are still items that need to
		// be processed.  The select statement will never select a nil
		// channel.
		var validateChan chan int32
		var uRootHintHeight int32
		if currentRoot < allRoots {
			validateChan = mn.pushWorkChan
			uRootHintHeight = mn.UtreexoRootHints[currentRoot].Height
		}
		select {
		case validateChan <- uRootHintHeight:
			btcdLog.Infof("Queuing root at height %v", uRootHintHeight)
			currentRoot++
		case processed := <-mn.rangeProcessed:
			btcdLog.Infof("Processed root at height:%v", processed.URootHint.Height)
			processedRoots++
			if !processed.Validated {
				// If a root is wrong, panic. The binary is incorrect
				// and there's no way of recovering from this.
				str := fmt.Sprintf("Root at height %d is invalid. The UtreexoRootHint in this code is incorrect",
					processed.URootHint.Height)
				panic(str)
			}
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
	Start()
	Stop()
	WaitForShutdown()
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
	getWorkChan    chan int32
	rangeProcessed chan *processedURootHint

	// Below are used to listen for the worker's server to finish verifying the
	// rootHint.
	valChan           chan bool
	inProcessRootHint *chaincfg.UtreexoRootHint
}

func NewRemoteWorker(num int8) Worker {
	rwrk := RemoteWorker{
		num:  num,
		quit: make(chan struct{}),
		//rangeProcessed: rangeProcessed,
		//getWorkChan:    getWorkChan,
		getWorkChan: make(chan int32, 1),
		valChan:     make(chan bool, 1),
	}
	return &rwrk
}

func (rwrk *RemoteWorker) GetWork() {
	// If we have this channel, we can have a blocking read
	// while also listening for the quit signal
	workChan := make(chan int32)
	go func() {
		// Tell the main node we're ready
		rwrk.coordCon.Write([]byte{})

		// grab the height from the main node
		buf := make([]byte, 4)
		rwrk.coordCon.Read(buf)
		height := int32(binary.BigEndian.Uint32(buf))
		workChan <- height
	}()

	select {
	case height := <-workChan:
		rwrk.getWorkChan <- height
		break
	case <-rwrk.quit:
		break
	}
}

func (rwrk *RemoteWorker) PushResults(*processedURootHint) {
}

func (rwrk *RemoteWorker) Start() {
	// Already started?
	if atomic.AddInt32(&rwrk.started, 1) != 1 {
		return
	}

	btcdLog.Trace("Starting utreexo remote worker")
	btcdLog.Infof("Starting utreexo remote worker")

	dialAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:5555")
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

// workHandler is the main workhorse for recieving utreexo roots to verify. workHandler
// must be called as a goroutine.
func (rwrk *RemoteWorker) workHandler() {
out:
	for {
		// If we're in the process of verifying something, block here and don't
		// queue up for another rootHint
		if rwrk.inProcessRootHint != nil {
			select {
			case verified := <-rwrk.valChan:
				// TODO push here
				rwrk.PushResults(
					&processedURootHint{
						Validated: verified,
						URootHint: rwrk.inProcessRootHint,
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
	getWorkChan    chan int32
	getWorkChanLol chan int32
	rangeProcessed chan *processedURootHint

	// Below are used to listen for the worker's server to finish verifying the
	// rootHint.
	valChan           chan bool
	inProcessRootHint *chaincfg.UtreexoRootHint
}

func (wrk *LocalWorker) GetWork() {
	height, ok := <-wrk.getWorkChan
	if ok {
		wrk.getWorkChanLol <- height
	}
}

func (wrk *LocalWorker) PushResults(result *processedURootHint) {
	wrk.rangeProcessed <- result
}

func NewLocalWorker(getWorkChan chan int32, rangeProcessed chan *processedURootHint, num int32) Worker {
	wrk := LocalWorker{
		num:            num,
		quit:           make(chan struct{}),
		rangeProcessed: rangeProcessed,
		getWorkChan:    getWorkChan,
		getWorkChanLol: make(chan int32, 1),
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
						Validated: verified,
						URootHint: wrk.inProcessRootHint,
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
		case uRootHintToVerifyHeight, ok := <-wrk.getWorkChanLol:
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
