// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Copyright (c) 2020-2021 The Utreexo developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"container/list"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/netsync"
	"github.com/btcsuite/btcd/wire"
)

const (
	MagicBytes   uint32 = 0xd9b4befa
	NewNodeReady uint32 = 0xfffffffa
	HeaderSize   uint32 = 20
	CommandSize  uint32 = 12
)

type work struct {
	uRootHintHeight int32
}

type result struct {
	uRootHintHeight int32
	valid           [1]byte
}

type startHeaders struct {
	lastHeight int32
	headers    []*wire.BlockHeader
	hashes     []chainhash.Hash
}

// MainNode is the main node for doing the initial block download. MainNode hands
// off work to other nodes if they are available.
type MainNode struct {
	started       int32
	shutdown      int32
	wg            sync.WaitGroup
	quit          chan struct{}
	refresh       chan struct{}
	gotAllHeaders chan struct{}

	// numWorkers is the amount of workers that are available to perform
	// the initial block download.
	numWorkers int32

	// all the available workers
	workers []*LocalWorker

	// server is the underlying btcd server
	server       *server
	startHeaders *startHeaders

	// The UtreexoRootHints that this MainNode must verify to complete
	// the initial block download.
	UtreexoRootHints []int32

	// Below are used to communicate with the workers.
	rangeProcessed chan *netsync.ProcessedURootHint
	pushWorkChan   chan *work
}

// initializes the UtreexoRootHintsToVerify
func initUtreexoRootHintsToVerify(chainParams *chaincfg.Params) []int32 {
	// init capacity based on the length of the hardcoded root hints.
	rootHints := make([]int32, 0,
		len(chainParams.UtreexoRootHints))

	for i := len(chainParams.UtreexoRootHints) - 1; i >= 0; i-- {
		rootHints = append(rootHints, chainParams.UtreexoRootHints[i].Height)
		//for _, rootHint := range chainParams.UtreexoRootHints {
		//rootHints = append(rootHints, rootHint.Height)
	}

	return rootHints
}

// initMainNode initializes a new MainNode
func initMainNode(chainParams *chaincfg.Params, numWorkers int32) (*MainNode, error) {
	mn := MainNode{
		quit:          make(chan struct{}),
		refresh:       make(chan struct{}),
		gotAllHeaders: make(chan struct{}),
		numWorkers:    numWorkers,
	}
	mn.UtreexoRootHints = initUtreexoRootHintsToVerify(chainParams)
	mn.pushWorkChan = make(chan *work)
	mn.rangeProcessed = make(chan *netsync.ProcessedURootHint, len(mn.UtreexoRootHints))

	//mn.server = newServer()

	interrupt := make(chan struct{}) // something for newServer func compat
	var err error
	mn.server, err = newServer(cfg.Listeners, cfg.AgentBlacklist,
		cfg.AgentWhitelist, nil, activeNetParams.Params, interrupt)
	if err != nil {
		btcdLog.Errorf("Unable to create server for the main node: %v", err)
		return nil, err
	}

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
	hi := netsync.ProcessedURootHint{}
	mn.rangeProcessed <- &hi
}

func (mn *MainNode) listenForRemoteWorkers() {
	var workerCount int
	listenAdr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:18330")
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

func (mn *MainNode) buildStartHeaders(uRootHint *chaincfg.UtreexoRootHint) error {
	var headers startHeaders
	msgHeaders := make([]*wire.BlockHeader, uRootHint.Height)
	blockHashes := make([]chainhash.Hash, uRootHint.Height)

	curHash := *uRootHint.Hash
	for i := uRootHint.Height - 1; i >= 0; i-- {
		newHeader, err := mn.server.chain.HeaderByHash(&curHash)
		if err != nil {
			return err
		}

		msgHeaders[i] = &newHeader
		blockHashes[i] = curHash
		curHash = newHeader.PrevBlock
	}
	fmt.Println("curHash", curHash.String())

	headers.headers = msgHeaders
	headers.hashes = blockHashes
	headers.lastHeight = uRootHint.Height

	mn.startHeaders = &headers

	return nil
}

func (mn *MainNode) grabStartHeaders() (*startHeaders, error) {
	return mn.startHeaders, nil
}

// remoteWorkerHandler is a function that listens for remote workers and writes
// a Utreexo root hint to be validated. This function behaves as a "worker" in that
// it'll listen to the mn.pushWorkChan/mn.rangeProcessed channels and take/push
// to those channels.
//
// This function MUST be ran as a goroutine
func (mn *MainNode) remoteWorkerHandler(conn net.Conn) {
	// block until we have all the headers
	select {
	case <-mn.gotAllHeaders:
		break
	case <-mn.quit:
		return
	}
	rootInProcess := make(map[int32]struct{})
out:
	for {
		// Listen to workers
		rmsg, _, err := ReadWorkerMessage(conn)
		if err != nil {
			btcdLog.Infof("remoteWorkerHandler errored out while reading message. Disconnecting remote worker. err: %s", err)
			break out
		}

		switch msg := rmsg.(type) {
		case *MsgGetStartHeaders:
			headers, err := mn.grabStartHeaders()
			if err != nil {
				panic(err)
			}

			msgStartHeaders := MsgStartHeaders{
				headers,
			}
			WriteWorkerMessage(conn, &msgStartHeaders)

		case *MsgGetWork:
			select {
			case work, ok := <-mn.pushWorkChan:
				if ok {
					msgWork := MsgWork{
						work,
					}
					WriteWorkerMessage(conn, &msgWork)
					rootInProcess[work.uRootHintHeight] = struct{}{}
				} else {
					break out
				}
			case <-mn.quit:
				break out
			}
		case *MsgResult:
			verification := msg.result.valid[:] //payload[:1]
			var valid bool
			if bytes.Equal(verification, []byte{0x01}) {
				valid = true
			}

			height := msg.result.uRootHintHeight
			mn.rangeProcessed <- &netsync.ProcessedURootHint{
				Validated:       valid,
				URootHintHeight: int32(height),
			}
			delete(rootInProcess, int32(height))
		default:
			btcdLog.Errorf("remoteWorkerHandler got an unknown message command of %s from remote worker", msg.Command())
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

// getHeaders does the initial header download to save time for the workers
func (mn *MainNode) getHeaders() {
	lastRootHint := mn.server.chain.FindLastRootHint()
	done := make(chan struct{})
	mn.server.StartHeadersDownload(lastRootHint, done)

	btcdLog.Infof("Downloading and verifying headers to last utreexo"+
		"root hint height of %v", lastRootHint.Height)

	select {
	case <-done:
		err := mn.buildStartHeaders(mn.server.chain.FindLastRootHint())
		if err != nil {
			panic(err)
		}
		btcdLog.Infof("Headers all downloaded")
		close(mn.gotAllHeaders)
		break
	case <-mn.quit:
		break
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

	// Start the remote worker handler. This handles the network connections to
	// communicate with remote workers.
	go mn.listenForRemoteWorkers()

	// first get all the headers to the last rootHint height
	mn.getHeaders()

	// Queue all the rootHints to be validated
	allRoots := len(mn.UtreexoRootHints)
	processedRoots := 0

out:
	for processedRoots < allRoots {
		// Only send items while there are still items that need to
		// be processed.  The select statement will never select a nil
		// channel.
		var validateChan chan *work
		workToQueue := work{}
		if len(mn.UtreexoRootHints) > 0 {
			validateChan = mn.pushWorkChan

			// grab from the queue
			height := mn.UtreexoRootHints[len(mn.UtreexoRootHints)-1]
			workToQueue.uRootHintHeight = height
		}

		select {
		case validateChan <- &workToQueue:
			// pop from the queue
			mn.UtreexoRootHints = mn.UtreexoRootHints[:len(mn.UtreexoRootHints)-1]
			btcdLog.Infof("Queuing root at height %v", workToQueue.uRootHintHeight)
		case processed := <-mn.rangeProcessed:
			btcdLog.Infof("Processed root at height:%v", processed.URootHintHeight)
			processedRoots++
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
	PushResults(*netsync.ProcessedURootHint)
}

type headerState struct {
	index      *blockchain.SharedBlockIndex
	headers    []*wire.BlockHeader
	hashes     []chainhash.Hash
	headerList *list.List
}

type RemoteWorker struct {
	num        int8
	started    int32
	shutdown   int32
	verifying  int32
	wg         sync.WaitGroup
	quit       chan struct{}
	headersSet chan struct{}

	// server is the underlying btcd server.
	server      *server
	headerState *headerState

	// Below are used to communicate with the main node.
	coordCon       net.Conn
	workChan       chan *work
	getWorkChan    chan *work
	rangeProcessed chan *netsync.ProcessedURootHint

	// Below are used to listen for the worker's server to finish verifying the
	// rootHint.
	valChan            chan netsync.ProcessedURootHint
	inProcessRootHints map[int32]struct{}
}

func NewRemoteWorker(num int8, hState *headerState) (*RemoteWorker, error) {
	rwrk := RemoteWorker{
		num:                num,
		quit:               make(chan struct{}),
		headersSet:         make(chan struct{}),
		getWorkChan:        make(chan *work, 1),
		workChan:           make(chan *work, 5),
		valChan:            make(chan netsync.ProcessedURootHint, 100),
		inProcessRootHints: make(map[int32]struct{}),
	}

	interrupt := make(chan struct{}) // something for newServer func compat
	newServer, err := newServer(cfg.Listeners, cfg.AgentBlacklist,
		cfg.AgentWhitelist, nil, activeNetParams.Params, interrupt)
	if err != nil {
		btcdLog.Errorf("Unable to create server for the worker: %v", err)
		return nil, err
	}
	rwrk.server = newServer
	rwrk.server.syncManager.SetHeaderList(hState.headerList)
	rwrk.server.chain.SetBlockIndex(hState.index)
	return &rwrk, nil
}

func (rwrk *RemoteWorker) GetWork() {
	// If we have this channel, we can have a blocking read
	// while also listening for the quit signal
	msg, err := makeEmptyMessage(CmdGetWork)
	if err != nil {
		panic(err)
	}
	err = WriteWorkerMessage(rwrk.coordCon, msg)
	if err != nil {
		panic(err)
	}

	select {
	case work := <-rwrk.workChan:
		rwrk.getWorkChan <- work
		break
	case <-rwrk.quit:
		break
	}
}

// queueWorker get a utreexo root hint from the coordinator node and then queues it
// to be verified by the sync manager.
//
// queueWorker must be run as a goroutine
func (rwrk *RemoteWorker) queueWorker() {
out:
	for {
		rwrk.GetWork()
		// TODO receive work here
		select {
		case work, ok := <-rwrk.getWorkChan:
			if ok {
				btcdLog.Tracef("Work received for rootHint height:%v for worker:%v",
					work, rwrk.num)

				// Grab the rootHint for the provided height. If nil, then panic since the
				// worker's rootHints are different from that of the main node
				uRootHint := rwrk.server.chain.FindRootHintByHeight(work.uRootHintHeight)
				var height int32
				if uRootHint != nil {
					height = uRootHint.Height
				}
				rwrk.inProcessRootHints[height] = struct{}{}
				rwrk.server.syncManager.QueueURootHint(uRootHint)
			} else {
				break out
			}
		case <-rwrk.quit:
			break out
		}
	}
}

func (rwrk *RemoteWorker) PushResults(p *netsync.ProcessedURootHint) {
	res := result{
		uRootHintHeight: p.URootHintHeight,
	}
	if p.Validated {
		res.valid = [1]byte{0x01}
	} else {
		res.valid = [1]byte{0x00}
	}

	msgResult := MsgResult{}
	msgResult.result = &res

	WriteWorkerMessage(rwrk.coordCon, &msgResult)
}

func (rwrk *RemoteWorker) Start() {
	// Already started?
	if atomic.AddInt32(&rwrk.started, 1) != 1 {
		return
	}

	btcdLog.Infof("Starting utreexo remote worker")

	dialAddr, err := net.ResolveTCPAddr("tcp", cfg.MainNodeIP+":18330")
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

func InitBlockIndex() (*headerState, error) {
	dialAddr, err := net.ResolveTCPAddr("tcp", cfg.MainNodeIP+":18330")
	if err != nil {
		btcdLog.Errorf("Couldn't resolve TCP addr err: %s", err)
	}

	coordCon, err := net.DialTCP("tcp", nil, dialAddr)
	if err != nil {
		btcdLog.Warnf("Couldn't connect to coordinator at %v, err: %s",
			dialAddr, err)
	}
	defer coordCon.Close()
	// Get the entire headers first
	msg, err := makeEmptyMessage(CmdGetStartHeaders)
	if err != nil {
		panic(err)
	}
	err = WriteWorkerMessage(coordCon, msg)
	if err != nil {
		panic(err)
	}

	rmsg, _, err := ReadWorkerMessage(coordCon)
	if err != nil {
		btcdLog.Errorf("InitBlockIndex errored while reading message err: %s", err)
		return nil, err
	}

	headerState := headerState{}
	switch msg := rmsg.(type) {
	case *MsgStartHeaders:
		btcdLog.Infof("Creating a shared blockindex...")
		index, err := blockchain.InitAndSetBIdx(msg.headers.headers[:], msg.headers.hashes[:], activeNetParams.Params)
		if err != nil {
			return nil, err
		}
		headerState.index = index
		headerState.headers = msg.headers.headers
		headerState.hashes = msg.headers.hashes
		headerState.headerList, err = createHeaderList(msg.headers.headers, msg.headers.hashes)
		if err != nil {
			return nil, err
		}
	default:
		err = fmt.Errorf("workHandler got an unknown message command of %s from the mainnode", rmsg.Command())
		return nil, err

	}

	return &headerState, nil

}

func (rwrk *RemoteWorker) setHeaders(msg *MsgStartHeaders) error {
	btcdLog.Infof("Creating blockindex...")
	index, err := blockchain.InitAndSetBIdx(msg.headers.headers[:], msg.headers.hashes[:], activeNetParams.Params)
	if err != nil {
		panic(err)
	}
	rwrk.headerState = &headerState{
		index:   index,
		headers: msg.headers.headers,
		hashes:  msg.headers.hashes,
	}
	rwrk.headerState.headerList, err = createHeaderList(msg.headers.headers, msg.headers.hashes)
	if err != nil {
		panic(err)
	}

	rwrk.headersSet <- struct{}{}

	return nil
}

func createHeaderList(headers []*wire.BlockHeader, hashes []chainhash.Hash) (*list.List, error) {
	var height int32
	headerList := list.New()

	for i, _ := range headers {
		height++
		blockHash := hashes[i]

		node := netsync.HeaderNode{Hash: &blockHash}
		node.Height = height
		headerList.PushBack(&node)
	}

	return headerList, nil
}

func (rwrk *RemoteWorker) listen() {
funcout:
	for {
		rmsg, _, err := ReadWorkerMessage(rwrk.coordCon)
		if err != nil {
			btcdLog.Errorf("RemoteWorker listen errored while reading message err: %s", err)
			break funcout
		}

		switch msg := rmsg.(type) {
		case *MsgWork:
			rwrk.workChan <- msg.work
		default:
			btcdLog.Errorf("workHandler got an unknown message command of %s from the mainnode", rmsg.Command())

		}
	}
}

// workHandler is the main workhorse for recieving utreexo roots to verify. workHandler
// must be called as a goroutine.
func (rwrk *RemoteWorker) workHandler() {
	// listen for messages from the coordinator
	go rwrk.listen()

	rwrk.server.StartUtreexoRootHintVerify(rwrk.valChan)

out:
	for {

		// If we're in the process of verifying something, block here and don't
		// queue up for another rootHint
		if len(rwrk.inProcessRootHints) > 0 {
			btcdLog.Infof("Enter block with queue of %d",
				len(rwrk.inProcessRootHints))
			select {
			case verified := <-rwrk.valChan:
				btcdLog.Infof("verified root at height %d",
					verified.URootHintHeight)
				rwrk.PushResults(&verified)

				// set inProcessRootHint to nil since we're not
				// verifying anything anymore
				delete(rwrk.inProcessRootHints, verified.URootHintHeight)
			case <-rwrk.quit:
				break out
			}
		}

		// We're not verifying anything at the moment so queue up for a rootHint
		btcdLog.Tracef("remote worker num %v queuing for work", rwrk.num)
		btcdLog.Infof("remote worker num %v queuing for work", rwrk.num)

		rwrk.GetWork()
		// TODO receive work here
		select {
		case work, ok := <-rwrk.getWorkChan:
			if ok {
				btcdLog.Tracef("Work received for rootHint height:%v for worker:%v",
					work, rwrk.num)

				// Grab the rootHint for the provided height. If nil, then panic since the
				// worker's rootHints are different from that of the main node
				uRootHint := rwrk.server.chain.FindRootHintByHeight(work.uRootHintHeight)
				var height int32
				if uRootHint != nil {
					height = uRootHint.Height
				}
				rwrk.inProcessRootHints[height] = struct{}{}

				rwrk.server.syncManager.QueueURootHint(uRootHint)
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
	coordChan      chan *work
	getWorkChan    chan *work
	rangeProcessed chan *netsync.ProcessedURootHint

	// Below are used to listen for the worker's server to finish verifying the
	// rootHint.
	valChan           chan netsync.ProcessedURootHint
	inProcessRootHint *chaincfg.UtreexoRootHint
}

func (wrk *LocalWorker) GetWork() {
	work, ok := <-wrk.coordChan
	if ok {
		wrk.getWorkChan <- work
	}
}

func (wrk *LocalWorker) PushResults(result *netsync.ProcessedURootHint) {
	wrk.rangeProcessed <- result
}

func NewLocalWorker(coordChan chan *work, rangeProcessed chan *netsync.ProcessedURootHint, num int32) *LocalWorker {
	wrk := LocalWorker{
		num:            num,
		quit:           make(chan struct{}),
		rangeProcessed: rangeProcessed,
		coordChan:      coordChan,
		getWorkChan:    make(chan *work, 1),
		valChan:        make(chan netsync.ProcessedURootHint, 1),
	}

	return &wrk
}

func (wrk *LocalWorker) Start() {
	// Already started?
	if atomic.AddInt32(&wrk.started, 1) != 1 {
		return
	}

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
				wrk.PushResults(&verified)
				//wrk.PushResults(
				//	&netsync.ProcessedURootHint{
				//		Validated:       verified,
				//		URootHintHeight: wrk.inProcessRootHint.Height,
				//	},
				//)

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
		case uRootHintWork, ok := <-wrk.getWorkChan:
			if ok {
				btcdLog.Infof("Work received for rootHint height:%v for worker:%v",
					uRootHintWork.uRootHintHeight, wrk.num)

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
				wrk.inProcessRootHint = wrk.server.chain.FindRootHintByHeight(uRootHintWork.uRootHintHeight)
				if wrk.inProcessRootHint == nil {
					err = fmt.Errorf("Unable to find the Utreexo Root Hint for height: %v. Panicking...", uRootHintWork.uRootHintHeight)
					btcdLog.Errorf("%s", err)
					panic(err)
				}

				wrk.server.StartUtreexoRootHintVerify(wrk.valChan)
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
