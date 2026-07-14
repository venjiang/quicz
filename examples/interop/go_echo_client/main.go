// Command go_echo_client opens two QUIC streams to the local Zig echo example.
//
// It is intentionally a local-development example. Supply the PEM trust anchor
// published with the Zig echo server; certificate verification stays enabled.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
)

func main() {
	address := flag.String("addr", "127.0.0.1:4443", "Zig QUIC server address")
	alpn := flag.String("alpn", "hq-interop", "required QUIC ALPN")
	caPath := flag.String("ca", "", "PEM trust anchor for the Zig echo server (required)")
	serverName := flag.String("server-name", "localhost", "TLS server name")
	flag.Parse()

	if *caPath == "" {
		log.Fatal("-ca is required")
	}
	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		log.Fatalf("read CA bundle %s: %v", *caPath, err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		log.Fatalf("parse CA bundle %s", *caPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connection, err := quic.DialAddr(ctx, *address, &tls.Config{
		RootCAs:    rootCAs,
		ServerName: *serverName,
		NextProtos: []string{*alpn},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{})
	if err != nil {
		log.Fatalf("dial %s: %v", *address, err)
	}
	defer connection.CloseWithError(0, "example complete")

	echoBytes := 0
	for _, message := range []string{"hello", "world"} {
		stream, err := connection.OpenStreamSync(ctx)
		if err != nil {
			log.Fatalf("open stream: %v", err)
		}
		if _, err := stream.Write([]byte(message)); err != nil {
			log.Fatalf("write stream: %v", err)
		}
		if err := stream.Close(); err != nil {
			log.Fatalf("finish stream: %v", err)
		}

		echoed := make([]byte, len(message))
		if _, err := io.ReadFull(stream, echoed); err != nil {
			log.Fatalf("read echo: %v", err)
		}
		if string(echoed) != message {
			log.Fatalf("unexpected echo %q", echoed)
		}
		var terminal [1]byte
		if n, err := stream.Read(terminal[:]); n != 0 || err != io.EOF {
			log.Fatalf("read echo FIN: bytes=%d err=%v", n, err)
		}
		echoBytes += len(echoed)
	}

	fmt.Printf("go_quic_echo_client: handshake_done=true echo_streams=2 echo_bytes=%d\n", echoBytes)
}
