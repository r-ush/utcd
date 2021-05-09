module github.com/btcsuite/btcd

require (
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/btcutil v1.0.2
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd
	github.com/btcsuite/goleveldb v1.0.0
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792
	github.com/btcsuite/winsvc v1.0.0
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/lru v1.0.0
	github.com/jessevdk/go-flags v1.4.0
	github.com/jrick/logrotate v1.0.0
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/mit-dci/utreexo v0.0.0-20210315015810-f7abca0043fb
	github.com/piotrnar/gocoin v0.0.0-20210221093853-ec4713336ba8
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
)

go 1.15

replace github.com/btcsuite/btcutil => github.com/mit-dci/utcutil v1.0.3-0.20210413154336-a1ad35fe261e
replace github.com/mit-dci/utreexo => github.com/kcalvinalvin/utreexo v0.0.0-20210509183109-a3d3cd2e3b33
replace github.com/piotrnar/gocoin => /home/calvin/bitcoin-projects/go/utreexo1/go/src/github.com/piotrnar/gocoin
