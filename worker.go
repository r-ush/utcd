// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Copyright (c) 2020-2021 The Utreexo developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
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
	getWorkChan chan *chaincfg.UtreexoRootHint
}

// MainNode is the main node for doing the initial block download. MainNode hands
// off work to other nodes if they are available.
type MainNode struct {
	started  int32
	shutdown int32
	wg       sync.WaitGroup
	quit     chan struct{}

	// is the MainNode also a worker?
	worker bool

	// numWorkers is the amount of workers that are available to perform
	// the initial block download.
	numWorkers int32

	// all the available workers
	workers []*Worker

	// server is the underlying btcd server.
	server *server

	// The UtreexoRootHints that this MainNode must verify to complete
	// the initial block download.
	UtreexoRootHints []chaincfg.UtreexoRootHint

	rangeProcessed chan *processedURootHint
	pushWorkChan   chan *chaincfg.UtreexoRootHint
	getWorkChan    chan *chaincfg.UtreexoRootHint
}

// initMainNode initializes a new MainNode
func initMainNode(chainParams *chaincfg.Params, numWorkers int32) (*MainNode, error) {
	mn := MainNode{
		quit:       make(chan struct{}),
		numWorkers: numWorkers,
	}
	mn.UtreexoRootHints = chainParams.UtreexoRootHints
	//mn.getWorkChan = make(chan *chaincfg.UtreexoRootHint)
	fmt.Println(len(mn.UtreexoRootHints))
	//mn.pushWorkChan = make(chan *workerChan, len(mn.UtreexoRootHints))
	mn.pushWorkChan = make(chan *chaincfg.UtreexoRootHint)
	mn.rangeProcessed = make(chan *processedURootHint, len(mn.UtreexoRootHints))

	interrupt := make(chan struct{}) // something for newServer func compat
	newServer, err := newServer(cfg.Listeners, cfg.AgentBlacklist,
		cfg.AgentWhitelist, nil, activeNetParams.Params, interrupt)
	if err != nil {
		return nil, err
	}
	mn.server = newServer
	return &mn, nil
}

func (mn *MainNode) Start() {
	// Already started?
	if atomic.AddInt32(&mn.started, 1) != 1 {
		return
	}

	btcdLog.Trace("Starting utreexo main node")
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

//// QueueUtreexoRootHint queues a utreexo root hint to a worker to be verified.
//func (mn *MainNode) QueueUtreexoRootHint(rootHint *chaincfg.UtreexoRootHint) bool {
//	mn.getWorkChan <- rootHint
//
//	validated := <-mn.rangeProcessed
//	return validated
//}

// QueueRootsToValidate pushes all the UtreexoRootHints that are hardcoded.
func (mn *MainNode) QueueRootsToValidate() {
	for _, rootHint := range mn.UtreexoRootHints {
		btcdLog.Infof("Queuing work for rootHint at height:%v", rootHint.Height)
		mn.pushWorkChan <- &rootHint
		//select {
		//case worker := <-mn.pushWorkChan:
		//	worker.getWorkChan <- &rootHint
		//	btcdLog.Infof("Queuing work for rootHint at height:%v for worker:%v", rootHint.Height, worker.num)
		//case <-mn.quit:
		//	break
		//}
		//if i >= 1 {
		//	return
		//}
	}
	close(mn.pushWorkChan)
	fmt.Println("Done QueueRootsToValidate")
}

func (mn *MainNode) workHandler() {
	workers := make([]*Worker, 0, mn.numWorkers)
	// Start all the workers
	for i := int32(0); i < mn.numWorkers; i++ {
		nw := NewWorker(mn.pushWorkChan, mn.rangeProcessed, i)
		workers = append(workers, nw)
		nw.Start()
	}

	// Queue all the rootHints to be validated
	allRoots := len(mn.UtreexoRootHints)
	currentRoot := 0
	processedRoots := 0

out:
	for processedRoots < allRoots {
		var validateChan chan *chaincfg.UtreexoRootHint
		var uRootHint *chaincfg.UtreexoRootHint
		if currentRoot < allRoots {
			validateChan = mn.pushWorkChan
			uRootHint = &mn.UtreexoRootHints[currentRoot]
		}
		select {
		case validateChan <- uRootHint:
			btcdLog.Infof("Queuing root at height %v", uRootHint.Height)
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
	for _, worker := range workers {
		worker.Stop()
		worker.WaitForShutdown()
	}

	mn.server.Stop()
	mn.server.WaitForShutdown()
	mn.wg.Done()
	btcdLog.Trace("work handler done")
	fmt.Println("Done")
}

// Worker is the UtreexoRootHint verifying worker that is in itself, a completely
// independent utreexo full node. It has a fully working server and will connect
// out to peers to download blocks. When it finishes verifying the UtreexoRootHint,
// it sends a message back to the main node that the UtreexoRootHint was verified.
type Worker struct {
	num       int32
	started   int32
	shutdown  int32
	verifying int32
	wg        sync.WaitGroup
	quit      chan struct{}

	// server is the underlying btcd server.
	server *server

	workChan       *workerChan
	getWorkChan    chan *chaincfg.UtreexoRootHint
	rangeProcessed chan *processedURootHint

	//valChan           chan bool
	//inProcessRootHint *chaincfg.UtreexoRootHint
}

func NewWorker(getWorkChan chan *chaincfg.UtreexoRootHint, rangeProcessed chan *processedURootHint, num int32) *Worker {
	wrk := Worker{
		num:            num,
		quit:           make(chan struct{}),
		rangeProcessed: rangeProcessed,
		getWorkChan:    getWorkChan,
		//valChan:        make(chan bool, 1),
		workChan: &workerChan{num,
			make(chan *chaincfg.UtreexoRootHint, 1)},
	}
	return &wrk
}

func (wrk *Worker) Start() {
	// Already started?
	if atomic.AddInt32(&wrk.started, 1) != 1 {
		return
	}

	btcdLog.Trace("Starting utreexo worker")
	btcdLog.Infof("Starting utreexo worker")
	wrk.wg.Add(1)
	go wrk.workHandler()
}

func (wrk *Worker) Stop() {
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
func (wrk *Worker) WaitForShutdown() {
	wrk.wg.Wait()
}

// isVerifying returns if the worker is currently busy verifying a utreexo
// root hint.
func (wrk *Worker) isVerifying() bool {
	return atomic.AddInt32(&wrk.verifying, 1) != 1
}

//// QueueUtreexoRootHint queues a utreexo root hint to a worker to be verified.
//func (wrk *Worker) QueueUtreexoRootHint(rootHint *chaincfg.UtreexoRootHint) (bool, int32) {
//	wrk.getWorkChan <- rootHint
//
//	validated := <-wrk.rangeProcessed
//	return validated, rootHint.Height
//}

// workHandler is the main workhorse for recieving utreexo roots to verify. workHandler
// must be called as a goroutine.
func (wrk *Worker) workHandler() {
	// async func lisening for quit
	go func() {
		select {
		case <-wrk.quit:
			close(wrk.getWorkChan)
			wrk.server.Stop()
			wrk.server.WaitForShutdown()

			wrk.wg.Done()
			btcdLog.Trace("work handler done")
		}
	}()
out:
	for {
		btcdLog.Infof("worker num %v queuing for work", wrk.num)
		select {
		case uRootHintToVerify, ok := <-wrk.getWorkChan:
			if ok {
				btcdLog.Infof("Work received for rootHint height:%v for worker:%v",
					uRootHintToVerify.Height, wrk.num)
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

				//wrk.inProcessRootHint = uRootHintToVerify
				valChan := make(chan bool, 1)

				wrk.server.StartUtreexoRootHintVerify(uRootHintToVerify, valChan)
				verified := <-valChan
				fmt.Println("verified", verified)
				wrk.rangeProcessed <- &processedURootHint{
					Validated: verified,
					URootHint: uRootHintToVerify,
				}
			} else {
				break out
			}
		}
		//case verified := <-wrk.valChan:
		//	//verified := <-valChan
		//	fmt.Println("verified", verified)
		//	wrk.rangeProcessed <- &processedURootHint{
		//		Validated: verified,
		//		URootHint: wrk.inProcessRootHint,
		//	}
		//	wrk.inProcessRootHint = nil
		//case <-wrk.quit:
		//	break out
		//}
	}

	wrk.server.Stop()
	wrk.server.WaitForShutdown()

	wrk.wg.Done()
	btcdLog.Trace("work handler done")
}
