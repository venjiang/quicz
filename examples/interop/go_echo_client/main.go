// Command go_echo_client opens two QUIC streams to the local Zig echo example.
//
// It is intentionally a local-development example. Supply the PEM trust anchor
// published with the Zig echo server; certificate verification stays enabled.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
)

// dropInboundPacketBurstConn discards a bounded burst of post-handshake UDP
// datagrams before exposing subsequent datagrams to quic-go. It is used only
// by the PTO probe to force the server's recovery deadline to expire.
type dropInboundPacketBurstConn struct {
	net.PacketConn
	droppingEnabled atomic.Bool
	droppedCount    atomic.Uint32
	dropLimit       uint32
}

func (connection *dropInboundPacketBurstConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	for {
		n, address, err := connection.PacketConn.ReadFrom(packet)
		if err != nil {
			return n, address, err
		}
		if connection.droppingEnabled.Load() {
			droppedCount := connection.droppedCount.Load()
			if droppedCount < connection.dropLimit && connection.droppedCount.CompareAndSwap(droppedCount, droppedCount+1) {
				continue
			}
		}
		return n, address, nil
	}
}

func main() {
	address := flag.String("addr", "127.0.0.1:4443", "Zig QUIC server address")
	alpn := flag.String("alpn", "hq-interop", "required QUIC ALPN")
	caPath := flag.String("ca", "", "PEM trust anchor for the Zig echo server (required)")
	serverName := flag.String("server-name", "localhost", "TLS server name")
	expectStreamLimit := flag.Bool("expect-stream-limit", false, "require stream IDs 0 then 4 after a one-stream peer limit")
	expectReset := flag.Bool("expect-reset", false, "cancel stream 0 with RESET_STREAM error 41, then echo stream 4")
	expectStopSending := flag.Bool("expect-stop-sending", false, "require remote STOP_SENDING error 42 on stream 0, then echo stream 4")
	expectUni := flag.Bool("expect-uni", false, "send client unidirectional stream 2 and require server unidirectional stream 3")
	expectServerPTO := flag.Bool("expect-server-pto", false, "drop four post-stream Zig datagrams and require a PTO-recovered echo")
	flag.Parse()
	selectedProbeCount := 0
	for _, enabled := range []bool{*expectStreamLimit, *expectReset, *expectStopSending, *expectUni, *expectServerPTO} {
		if enabled {
			selectedProbeCount++
		}
	}
	if selectedProbeCount > 1 {
		log.Fatal("stream-limit, reset, stop-sending, uni, and server-PTO probes are mutually exclusive")
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

	tlsConfig := &tls.Config{
		RootCAs:    rootCAs,
		ServerName: *serverName,
		NextProtos: []string{*alpn},
		MinVersion: tls.VersionTLS13,
	}
	var connection *quic.Conn
	var dropConnection *dropInboundPacketBurstConn
	if *expectServerPTO {
		udpConnection, err := net.ListenUDP("udp", nil)
		if err != nil {
			log.Fatalf("listen UDP for PTO probe: %v", err)
		}
		defer udpConnection.Close()
		dropConnection = &dropInboundPacketBurstConn{
			PacketConn: udpConnection,
			dropLimit:  4,
		}
		peerAddress, err := net.ResolveUDPAddr("udp", *address)
		if err != nil {
			log.Fatalf("resolve %s: %v", *address, err)
		}
		connection, err = quic.Dial(ctx, dropConnection, peerAddress, tlsConfig, &quic.Config{})
	} else {
		connection, err = quic.DialAddr(ctx, *address, tlsConfig, &quic.Config{})
	}
	if err != nil {
		log.Fatalf("dial %s: %v", *address, err)
	}
	defer connection.CloseWithError(0, "example complete")
	if *expectUni {
		clientStream, err := connection.OpenUniStreamSync(ctx)
		if err != nil {
			log.Fatalf("open client unidirectional stream: %v", err)
		}
		if uint64(clientStream.StreamID()) != 2 {
			log.Fatalf("client unidirectional stream: got stream %d, want 2", clientStream.StreamID())
		}
		if _, err := clientStream.Write([]byte("uni")); err != nil {
			log.Fatalf("write client unidirectional stream: %v", err)
		}
		if err := clientStream.Close(); err != nil {
			log.Fatalf("finish client unidirectional stream: %v", err)
		}
		serverStream, err := connection.AcceptUniStream(ctx)
		if err != nil {
			log.Fatalf("accept server unidirectional stream: %v", err)
		}
		if uint64(serverStream.StreamID()) != 3 {
			log.Fatalf("server unidirectional stream: got stream %d, want 3", serverStream.StreamID())
		}
		payload, err := io.ReadAll(serverStream)
		if err != nil {
			log.Fatalf("read server unidirectional stream: %v", err)
		}
		if string(payload) != "uni-reply" {
			log.Fatalf("unexpected unidirectional payload %q", payload)
		}
		fmt.Printf("go_quic_uni_client: handshake_done=true client_stream=2 server_stream=3 reply_bytes=%d\n", len(payload))
		return
	}

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
	if *expectStopSending {
		stopStream, err := connection.OpenStreamSync(ctx)
		if err != nil {
			log.Fatalf("open stop-sending stream: %v", err)
		}
		if uint64(stopStream.StreamID()) != 0 {
			log.Fatalf("stop-sending stream: got stream %d, want 0", stopStream.StreamID())
		}
		if _, err := stopStream.Write([]byte("stop")); err != nil {
			log.Fatalf("write stop-sending stream: %v", err)
		}
		stopDeadline := time.Now().Add(2 * time.Second)
		for {
			_, err := stopStream.Write([]byte("x"))
			if err != nil {
				var streamErr *quic.StreamError
				if !errors.As(err, &streamErr) || !streamErr.Remote || streamErr.ErrorCode != 42 {
					log.Fatalf("stop-sending error: %v", err)
				}
				break
			}
			if time.Now().After(stopDeadline) {
				log.Fatal("timed out waiting for STOP_SENDING")
			}
			time.Sleep(5 * time.Millisecond)
		}
		messages = messages[1:]
		expectedFirstStreamID = 4
	}

	echoBytes := 0
	for streamIndex, message := range messages {
		stream, err := connection.OpenStreamSync(ctx)
		if err != nil {
			log.Fatalf("open stream: %v", err)
		}
		if *expectStreamLimit || *expectReset || *expectStopSending {
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
		if streamIndex == 0 && dropConnection != nil {
			dropConnection.droppingEnabled.Store(true)
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
	if *expectStopSending {
		fmt.Printf("go_quic_stop_sending_client: handshake_done=true stop_error=42 reset_error=42 echo_stream=4 echo_bytes=%d\n", echoBytes)
		return
	}
	if *expectServerPTO {
		if dropConnection.droppedCount.Load() < dropConnection.dropLimit {
			log.Fatal("PTO probe did not drop the expected post-handshake Zig datagrams")
		}
		fmt.Printf("go_quic_server_pto_client: handshake_done=true dropped_datagrams=%d echo_streams=2 echo_bytes=%d\n", dropConnection.dropLimit, echoBytes)
		return
	}
	fmt.Printf("go_quic_echo_client: handshake_done=true echo_streams=2 echo_bytes=%d\n", echoBytes)
}
