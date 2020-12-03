#!/usr/bin/env bash
#./btcd --datadir=. --utreexocsn --addpeer=127.0.0.1 --nolisten --nodnsseed -d=debug
./btcd --datadir=. --utreexocsn --addpeer=127.0.0.1 --nolisten --nodnsseed --rpcpass=calvin --rpcuser=calvin
