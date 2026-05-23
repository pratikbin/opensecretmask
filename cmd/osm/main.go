// Command osm is the opensecretmask CLI: a local CA-MITM proxy that masks
// secrets in LLM API traffic and restores them in the responses.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "osm: "+err.Error())
		os.Exit(1)
	}
}
