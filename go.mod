module github.com/btcsuite/btcd

go 1.14

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
	github.com/mit-dci/utreexo v0.0.0-20201228143410-ba535a0beae8
	github.com/syndtr/goleveldb v1.0.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
)

replace github.com/btcsuite/btcutil => github.com/mit-dci/utcutil v1.0.3-0.20210128061119-1d9d9d57ced6
replace github.com/mit-dci/utreexo => github.com/kcalvinalvin/utreexo v0.0.0-20210129145908-3856211d3d90
