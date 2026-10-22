package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestConfiguredEndpointTargetUsesOnlyValidLanConfiguration(t *testing.T) {
	configuration := networkConfiguration{
		Scope:          "lan",
		AuthorityPort:  8920,
		BindAddress:    "192.168.1.12",
		ClientHostname: "manager.school.lan",
	}
	host, port, reason := configuredEndpointTarget(configuration)
	if reason != "" || host != "manager.school.lan" || port != 8920 {
		t.Fatalf("configured endpoint target = (%q, %d, %q)", host, port, reason)
	}

	configuration.ClientHostname = "manager.school.lan\ninvalid"
	if _, _, reason := configuredEndpointTarget(configuration); reason == "" {
		t.Fatal("hostname containing controls must not be probed")
	}

	configuration = networkConfiguration{
		Scope:         "lan",
		AuthorityPort: 8920,
		BindAddress:   "0.0.0.0",
	}
	if _, _, reason := configuredEndpointTarget(configuration); reason == "" {
		t.Fatal("wildcard bind address must not be used as a probe target")
	}

	configuration = networkConfiguration{Scope: "loopback_development", AuthorityPort: 8787}
	if _, _, reason := configuredEndpointTarget(configuration); reason == "" {
		t.Fatal("loopback development must not trigger a remote TLS probe")
	}
}

func TestEndpointIPLiteralSkipsDNSResolution(t *testing.T) {
	addresses, err := resolveEndpointAddresses(context.Background(), "192.168.1.12")
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("192.168.1.12") {
		t.Fatalf("resolved IP literal = (%v, %v)", addresses, err)
	}
	unique := uniqueSortedAddresses([]netip.Addr{
		netip.MustParseAddr("192.168.1.12"),
		netip.MustParseAddr("::ffff:192.168.1.12"),
		netip.MustParseAddr("192.168.1.2"),
	})
	if len(unique) != 2 || unique[0] != netip.MustParseAddr("192.168.1.2") ||
		unique[1] != netip.MustParseAddr("192.168.1.12") {
		t.Fatalf("deduplicated and sorted addresses = %v", unique)
	}
	private := privateProbeAddresses([]netip.Addr{
		netip.MustParseAddr("192.168.1.12"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("fd12:3456:789a::1"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("fe80::1"),
	})
	if len(private) != 2 || private[0] != netip.MustParseAddr("192.168.1.12") ||
		private[1] != netip.MustParseAddr("fd12:3456:789a::1") {
		t.Fatalf("LAN probe allowed non-private addresses: %v", private)
	}
}

func TestTLSProbeVerifiesHostnameAndReportsLeafFingerprint(t *testing.T) {
	certificate, roots := testProbeCertificate(t, "manager.school.lan")
	details := runPipeTLSProbe(t, certificate, roots, "manager.school.lan")
	if details.version == "" {
		t.Fatal("successful probe must report the negotiated TLS version")
	}
	want := sha256.Sum256(certificate.Certificate[0])
	if details.leafSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("leaf fingerprint = %q, want %x", details.leafSHA256, want)
	}
}

func TestTLSProbeRejectsCertificateForAnotherHostname(t *testing.T) {
	certificate, roots := testProbeCertificate(t, "manager.school.lan")
	_, err := certificate.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "other.school.lan",
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err == nil {
		t.Fatal("certificate verification must reject another hostname")
	}
	var hostnameError x509.HostnameError
	if !errors.As(err, &hostnameError) {
		t.Fatalf("verification error = %T, want hostname verification error", err)
	}
	if got := describeTLSProbeFailure(err); got != "The server certificate does not match the configured hostname." {
		t.Fatalf("reported failure = %q", got)
	}
	configuration := verifiedTLSClientConfig("other.school.lan", roots)
	if configuration.ServerName != "other.school.lan" || configuration.InsecureSkipVerify {
		t.Fatal("TLS probe must verify the configured hostname with normal certificate checks")
	}
}

func testProbeCertificate(t *testing.T, hostname string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 test key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create self-signed test certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: parsed}, roots
}

func runPipeTLSProbe(t *testing.T, certificate tls.Certificate, roots *x509.CertPool,
	serverName string) tlsProbeDetails {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	server := tls.Server(serverRaw, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer serverRaw.Close()
		_ = server.Handshake()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	details, err := inspectTLSConnection(ctx, clientRaw, serverName, roots)
	if err != nil {
		t.Fatalf("TLS probe failed: %v", err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("TLS test server did not finish its handshake")
	}
	return details
}
