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
	expectStreamLimit := flag.Bool("expect-stream-limit", false, "require stream IDs 0 then 4 after a one-stream peer limit")
	expectReset := flag.Bool("expect-reset", false, "cancel stream 0 with RESET_STREAM error 41, then echo stream 4")
	flag.Parse()
	if *expectStreamLimit && *expectReset {
		log.Fatal("-expect-stream-limit and -expect-reset are mutually exclusive")
	}

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

	messages := []string{"hello", "world"}
	expectedFirstStreamID := uint64(0)
	if *expectReset {
		resetStream, err := connection.OpenStreamSync(ctx)
		if err != nil {
			log.Fatalf("open reset stream: %v", err)
		}
		if uint64(resetStream.StreamID()) != 0 {
			log.Fatalf("reset stream: got stream %d, want 0", resetStream.StreamID())
		}
		resetStream.CancelWrite(41)
		messages = messages[1:]
		expectedFirstStreamID = 4
	}

	echoBytes := 0
	for streamIndex, message := range messages {
		stream, err := connection.OpenStreamSync(ctx)
		if err != nil {
			log.Fatalf("open stream: %v", err)
		}
		if *expectStreamLimit || *expectReset {
			expectedID := expectedFirstStreamID + uint64(streamIndex*4)
			if uint64(stream.StreamID()) != expectedID {
				log.Fatalf("unexpected stream: got %d, want %d", stream.StreamID(), expectedID)
			}
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

	if *expectStreamLimit {
		fmt.Printf("go_quic_stream_limit_client: handshake_done=true initial_limit=1 released_stream=4 echo_bytes=%d\n", echoBytes)
		return
	}
	if *expectReset {
		fmt.Printf("go_quic_reset_client: handshake_done=true reset_error=41 echo_stream=4 echo_bytes=%d\n", echoBytes)
		return
	}
	fmt.Printf("go_quic_echo_client: handshake_done=true echo_streams=2 echo_bytes=%d\n", echoBytes)
}
