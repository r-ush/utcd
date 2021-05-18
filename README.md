utcd
====

[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)

utcd is a fork of btcd, an alternative full node bitcoin implementation written in Go (golang).
utcd implements the Utreexo accumulator into btcd.

This project is currently under active development, but is a work in progress.
The current release is only a demo release and should be treated like so.

## Requirements

[Go](http://golang.org) 1.15 or newer.

## Build
Without secp256k1:
```bash
env CGO_ENABLED=0 go build
```

With secp256k1:
```bash
$ git submodule init
$ git submodule update
$ cd btcec/secp256k1
$ ./autogen.sh
$ ./configure --prefix=$PWD
$ make all
$ make check
$ make install
$ cd ../..
$ go build
```

Basically just build the secp256k1 library with --prefix set to the btcec/secp256k1 directory and then `go build`.
utcd with secp256k1 isn't supported on Windows.

## Getting Started

1: Running a bridgenode. For mainnet, at least 1tb of disk space is required.

```bash
./btcd --utreexo
```

2: Running a coordinator node

```bash
./btcd --utreexocsn --utreexomain --nolisten --norpc --blocksonly --connect=IP_OF_THE_BRIDGENODE
```

3: Running a worker node. Recommended to set --numworkers flag equal to that of the logical cores on your machine. --mainnodeip is also required if the coordinator node is on a remote machine.

```bash
./btcd --utreexocsn --utreexoworker --numworkers=1 --nolisten --nocfilters --norpc --blocksonly --connect=IP_OF_THE_BRIDGENODE --mainnodeip=IP_OF_THE_COORDINATOR_NODE
```

## Replicating IBD benchmarks

There were three setups completed for the IBD benchmarks:

1. Bridgenode and IBD node on two different machines.
  - Set up the bridgenode on a separate machine. Note the public ip address of this machine.
  - Run the coordinator node with flag --connect=IP_OF_THE_BRIDGENODE then run the worker node on the same machine also with --connect=IP_OF_THE_BRIDGENODE.
  - When the coordinator node is finished with the IBD, it'll display this log
  `2021-05-11 05:13:22.501 [INF] BTCD: Done verifying all roots`
  - Subtract the start time from this time.

2. Bridgenode and IBD node on the same machine.
  - Set up the bridgenode.
  - Run the coordinator node with flag --connect=127.0.0.1 then run the worker node on the same machine also with flag --connect=127.0.0.1
  - When the coordinator node is finished with the IBD, it'll display this log
  `2021-05-11 05:13:22.501 [INF] BTCD: Done verifying all roots`
  - Subtract the start time from this time.

3. Bridgenode and two IBD nodes for multi-machine IBD.
  - Set up the bridgenode on a separate machine. Note the public ip address of this machine.
  - Run the coordinator node with flag --connect=IP_OF_THE_BRIDGENODE then run the worker node on the same machine also with --connect=IP_OF_THE_BRIDGENODE. Note the public ip address of this machine.
    Port 18330 is used to communicate with a remote worker. You can change this port number by editing `worker.go`. Just find all the 18330s and replace with whatever port you want.
  - On a different machine, run a worker node with flag --mainnodeip=IP_OF_THE_COORDINATOR_NODE. Make sure the port 18330 is open on the coordinator node side.
  - When the coordinator node is finished with the IBD, it'll display this log
  `2021-05-11 05:13:22.501 [INF] BTCD: Done verifying all roots`
  - Subtract the start time from this time.

# IRC

- irc.freenode.net
- channel #utreexo

## License

utcd is licensed under the [copyfree](http://copyfree.org) ISC License.
