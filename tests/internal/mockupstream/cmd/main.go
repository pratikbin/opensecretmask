// mockupstream binary stands in for an LLM endpoint inside test containers.
// It reads the osm CA from --ca-dir, mints a TLS leaf signed by it, and
// serves an echo-and-record handler on 127.0.0.1:<port>. The bound address
// is printed as `listen=<host:port>` on stdout so the calling test can read
// it back.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pratikbin/opensecretmask/internal/proxy"
	"github.com/pratikbin/opensecretmask/tests/internal/mockupstream"
)

func main() {
	caDir := flag.String("ca-dir", "", "directory holding osm ca-cert.pem and ca-key.pem")
	port := flag.Int("port", 0, "listen port (0 = ephemeral)")
	flag.Parse()
	if *caDir == "" {
		log.Fatal("--ca-dir required")
	}
	ca, err := proxy.LoadCA(*caDir)
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}
	srv, err := mockupstream.New(ca, *port)
	if err != nil {
		log.Fatalf("start mockupstream: %v", err)
	}
	fmt.Printf("listen=%s\n", srv.Host)
	_ = os.Stdout.Sync()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	<-sigs
	_ = srv.Close()
}
