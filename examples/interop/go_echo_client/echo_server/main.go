// Command echo_server is a one-connection quic-go peer for the Zig external
// client example. It generates a localhost test certificate and writes its
// public certificate as the CA PEM supplied to quicz-interop-external-client.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
)

func main() {
	address := flag.String("addr", "127.0.0.1:4433", "UDP listen address")
	caOut := flag.String("ca-out", "", "PEM output path for the generated trust anchor (required)")
	flag.Parse()
	if *caOut == "" {
		log.Fatal("-ca-out is required")
	}

	certificate, certPEM, err := localhostCertificate()
	if err != nil {
		log.Fatalf("create certificate: %v", err)
	}
	if err := os.WriteFile(*caOut, certPEM, 0o600); err != nil {
		log.Fatalf("write CA PEM: %v", err)
	}
	listener, err := quic.ListenAddr(*address, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"hq-interop"},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{})
	if err != nil {
		log.Fatalf("listen %s: %v", *address, err)
	}
	defer listener.Close()
	log.Printf("go_quic_echo_server: listening=%s ca_out=%s", *address, *caOut)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := listener.Accept(ctx)
	if err != nil {
		log.Fatalf("accept connection: %v", err)
	}
	defer connection.CloseWithError(0, "example complete")

	echoBytes := 0
	for range 2 {
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			log.Fatalf("accept stream: %v", err)
		}
		payload, err := io.ReadAll(stream)
		if err != nil {
			log.Fatalf("read stream: %v", err)
		}
		if _, err := stream.Write(payload); err != nil {
			log.Fatalf("write stream: %v", err)
		}
		if err := stream.Close(); err != nil {
			log.Fatalf("finish stream: %v", err)
		}
		echoBytes += len(payload)
	}
	log.Printf("go_quic_echo_server: handshake_done=true echo_streams=2 echo_bytes=%d", echoBytes)
}

func localhostCertificate() (tls.Certificate, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
