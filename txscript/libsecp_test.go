package txscript

import (
	"fmt"
	"testing"
)

func TestLibSecpAvailable(t *testing.T) {
	if verify() {
		fmt.Println("libsecp available.")
	} else {
		fmt.Println("libsecp not available. Falling back to btcec")
	}
}
