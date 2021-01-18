#!/usr/bin/env bash
#./btcd --datadir=. --utreexocsn --addpeer=127.0.0.1 --nolisten --nodnsseed -d=debug
#./btcd --datadir=. --utreexocsn --addpeer=127.0.0.1 --nolisten --nodnsseed --rpcpass=calvin --rpcuser=calvin -d=debug
#./btcd --datadir=. --utreexocsn --addpeer=127.0.0.1 --nolisten --nodnsseed --testnet --norpc -d=debug
time ./btcd --datadir=. --utreexocsn --addpeer=127.0.0.1 --nolisten --nodnsseed --testnet --norpc --blocksonly --nocfilters --cpuprofile=cpuprof-utcd-client #-d=debug
#time ./btcd --datadir=. --addpeer=127.0.0.1 --nolisten --nodnsseed --testnet --norpc --blocksonly --nocfilters --cpuprofile=cpuprof-utcd-client #-d=debug
#time ./btcd --datadir=. --utreexocsn --addpeer=127.0.0.1 --nolisten --nodnsseed --testnet --norpc --blocksonly --nocfilters #-d=debug
#./btcd --datadir=. --utreexocsn --addpeer=127.0.0.1 --nolisten --nodnsseed --regtest --norpc

#time ./btcd --datadir=. --utreexocsn --addpeer=127.0.0.1 --nolisten --nodnsseed --rpcpass=calvin --rpcuser=calvin --cpuprofile=cpuprof-utcd
#time ./btcd --datadir=. --nolisten --rpcpass=calvin --rpcuser=calvin --cpuprofile=cpuprof-utcd --testnet --utreexo --blocksonly
#time ./btcd --datadir=. --nolisten --rpcpass=calvin --rpcuser=calvin --cpuprofile=cpuprof-utcd
