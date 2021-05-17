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

## Getting Started

utcd only supports utreexocsn mode and will only connect to the designated
nodes that we have set up. To run a bridge node and connect to it, you
must modify/build from source.

#### Linux/BSD/POSIX/Source

1: Running a bridgenode

```bash
./btcd --utreexo
```

2: Running a coordinator node

```bash
./btcd --utreexocsn --utreexomain --nolisten --norpc --blocksonly --connect=IP_OF_THE_BRIDGENODE
```

3: Running a coordinator node. Recommended to set --numworkers flag equal to that of the logical cores on your machine. --mainnodeip is also required if the coordinator node is on a remote machine.

```bash
./btcd --utreexocsn --utreexoworker --numworkers=1 --nolisten --nocfilters --norpc --blocksonly --connect=IP_OF_THE_BRIDGENODE --mainnodeip=IP_OF_THE_COORDINATOR_NODE
```

# IRC

- irc.freenode.net
- channel #utreexo

## License

utcd is licensed under the [copyfree](http://copyfree.org) ISC License.
