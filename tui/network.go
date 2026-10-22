package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

const (
	maxNetworkInterfaces   = 128
	maxNetworkAddresses    = 512
	maxDisplayedInterfaces = 32
	maxDisplayedAddresses  = 64
	maxNetworkWarnings     = 16
	maxResolverBytes       = 64 << 10
	maxProbeAddresses      = 8
	networkProbeTimeout    = 5 * time.Second
)

type networkInterfaceDiagnostic struct {
	name    string
	up      bool
	address []string
}

type networkDiagnostics struct {
	capturedAt        time.Time
	interfaces        []networkInterfaceDiagnostic
	addressCount      int
	nameservers       []string
	resolverInspected bool
	endpointProbe     *networkEndpointProbe
	warnings          []string
}

type networkEndpointProbe struct {
	target            string
	resolvedAddresses []string
	ignoredAddresses  int
	omittedAddresses  int
	dnsStatus         string
	connectedAddress  string
	tlsVersion        string
	tlsFingerprint    string
	tlsStatus         string
}

type networkDiagnosticsMessage struct {
	generation uint64
	report     networkDiagnostics
	err        error
}

func refreshNetworkDiagnostics(generation uint64, configuration networkConfiguration) tea.Cmd {
	return func() tea.Msg {
		report, err := collectNetworkDiagnostics(configuration)
		return networkDiagnosticsMessage{generation: generation, report: report, err: err}
	}
}

func (m model) currentNetworkConfiguration() networkConfiguration {
	if m.status == nil {
		return networkConfiguration{}
	}
	return m.status.Configuration.Network
}

func collectNetworkDiagnostics(configuration networkConfiguration) (networkDiagnostics, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return networkDiagnostics{}, fmt.Errorf("list local network interfaces: %w", err)
	}
	sort.Slice(interfaces, func(left, right int) bool {
		return interfaces[left].Name < interfaces[right].Name
	})

	report := networkDiagnostics{capturedAt: time.Now().UTC()}
	if len(interfaces) > maxNetworkInterfaces {
		report.warnings = appendBoundedWarning(report.warnings, "Interface listing was capped at 128 entries.")
		interfaces = interfaces[:maxNetworkInterfaces]
	}
	for _, iface := range interfaces {
		addresses, addressErr := iface.Addrs()
		if addressErr != nil {
			report.warnings = appendBoundedWarning(report.warnings, fmt.Sprintf(
				"Could not read addresses for interface %s.", strconv.QuoteToASCII(iface.Name)))
			continue
		}
		entry := networkInterfaceDiagnostic{name: iface.Name, up: iface.Flags&net.FlagUp != 0}
		for _, address := range addresses {
			if report.addressCount >= maxNetworkAddresses {
				report.warnings = appendBoundedWarning(report.warnings, "Address listing was capped at 512 entries.")
				break
			}
			canonical := canonicalNetworkAddress(address.String())
			if canonical == "" {
				report.warnings = appendBoundedWarning(report.warnings, "An interface address could not be parsed and was omitted.")
				continue
			}
			entry.address = append(entry.address, canonical)
			report.addressCount++
		}
		sort.Strings(entry.address)
		if len(entry.address) > 0 {
			report.interfaces = append(report.interfaces, entry)
		}
	}

	if runtime.GOOS == "linux" {
		report.resolverInspected = true
		nameservers, resolverErr := readResolverNameservers()
		if resolverErr != nil {
			report.warnings = appendBoundedWarning(report.warnings, "Could not inspect /etc/resolv.conf.")
		} else {
			report.nameservers = nameservers
			if len(nameservers) == 16 {
				report.warnings = appendBoundedWarning(report.warnings, "Resolver nameserver display is limited to 16 entries.")
			}
		}
	}
	report.endpointProbe = probeConfiguredEndpoint(configuration)
	return report, nil
}

// Probe only the saved LAN/private DNS endpoint; DNS results outside private ranges are
// never contacted, and no credentials or application data are sent.
func probeConfiguredEndpoint(configuration networkConfiguration) *networkEndpointProbe {
	host, port, reason := configuredEndpointTarget(configuration)
	if reason != "" {
		return &networkEndpointProbe{tlsStatus: reason}
	}

	probe := &networkEndpointProbe{target: net.JoinHostPort(host, strconv.Itoa(int(port)))}
	ctx, cancel := context.WithTimeout(context.Background(), networkProbeTimeout)
	defer cancel()
	addresses, err := resolveEndpointAddresses(ctx, host)
	if err != nil {
		probe.dnsStatus = describeDNSFailure(err)
		probe.tlsStatus = "Not checked because DNS resolution failed."
		return probe
	}
	addresses = uniqueSortedAddresses(addresses)
	if len(addresses) == 0 {
		probe.dnsStatus = "The configured name resolved to no IP addresses."
		probe.tlsStatus = "Not checked because DNS returned no addresses."
		return probe
	}
	resolvedCount := len(addresses)
	addresses = privateProbeAddresses(addresses)
	probe.ignoredAddresses = resolvedCount - len(addresses)
	if len(addresses) == 0 {
		probe.dnsStatus = "The configured hostname resolved only outside private address ranges."
		probe.tlsStatus = "Not checked because this screen probes private addresses only."
		return probe
	}
	probe.dnsStatus = "Resolved to private LAN address(es)."
	if len(addresses) > maxProbeAddresses {
		probe.omittedAddresses = len(addresses) - maxProbeAddresses
		addresses = addresses[:maxProbeAddresses]
	}
	for _, address := range addresses {
		probe.resolvedAddresses = append(probe.resolvedAddresses, address.String())
	}

	dialer := net.Dialer{Timeout: networkProbeTimeout}
	var lastErr error
	for _, address := range addresses {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}
		remoteAddress := net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
		connection, dialErr := dialer.DialContext(ctx, "tcp", remoteAddress)
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		probe.connectedAddress = connection.RemoteAddr().String()
		details, tlsErr := inspectTLSConnection(ctx, connection, host, nil)
		if tlsErr != nil {
			lastErr = tlsErr
			continue
		}
		probe.tlsVersion = details.version
		probe.tlsFingerprint = details.leafSHA256
		probe.tlsStatus = "Certificate verified for the configured hostname."
		return probe
	}
	probe.tlsStatus = describeTLSProbeFailure(lastErr)
	return probe
}

func resolveEndpointAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{address}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func configuredEndpointTarget(configuration networkConfiguration) (string, uint16, string) {
	if configuration.Scope != "lan" && configuration.Scope != "private_dns" {
		return "", 0, "Endpoint probe is only used for a saved LAN or private DNS deployment."
	}
	if configuration.AuthorityPort < 1024 || configuration.AuthorityPort == 8787 {
		return "", 0, "Saved authority port is invalid; endpoint probe was skipped."
	}
	host := strings.TrimSpace(configuration.ClientHostname)
	if host != "" {
		if !validClientHostname(host) {
			return "", 0, "Saved Manager hostname is invalid; endpoint probe was skipped."
		}
		return host, configuration.AuthorityPort, ""
	}
	address := net.ParseIP(strings.TrimSpace(configuration.BindAddress))
	if address == nil || !address.IsPrivate() || address.IsLoopback() ||
		address.IsUnspecified() || address.IsMulticast() {
		return "", 0, "Saved private bind address is invalid; endpoint probe was skipped."
	}
	return address.String(), configuration.AuthorityPort, ""
}

func uniqueSortedAddresses(addresses []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(addresses))
	unique := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		unique = append(unique, address)
	}
	sort.Slice(unique, func(left, right int) bool {
		return unique[left].Less(unique[right])
	})
	return unique
}

func privateProbeAddresses(addresses []netip.Addr) []netip.Addr {
	private := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.IsPrivate() && !address.IsLoopback() && !address.IsUnspecified() &&
			!address.IsMulticast() {
			private = append(private, address)
		}
	}
	return private
}

type tlsProbeDetails struct {
	version    string
	leafSHA256 string
}

func inspectTLSConnection(ctx context.Context, connection net.Conn, serverName string,
	rootCAs *x509.CertPool) (tlsProbeDetails, error) {
	defer connection.Close()
	tlsConnection := tls.Client(connection, verifiedTLSClientConfig(serverName, rootCAs))
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return tlsProbeDetails{}, err
	}
	state := tlsConnection.ConnectionState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		return tlsProbeDetails{}, errors.New("TLS peer certificate is unavailable")
	}
	fingerprint := sha256.Sum256(state.PeerCertificates[0].Raw)
	return tlsProbeDetails{
		version:    tls.VersionName(state.Version),
		leafSHA256: fmt.Sprintf("%x", fingerprint),
	}, nil
}

func verifiedTLSClientConfig(serverName string, rootCAs *x509.CertPool) *tls.Config {
	// In production rootCAs is nil, so Go uses the host trust store. Keep
	// hostname verification enabled for every probe.
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: serverName,
	}
}

func describeDNSFailure(err error) string {
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && dnsError.IsTimeout {
		return "DNS lookup timed out."
	}
	if errors.As(err, &dnsError) && dnsError.IsNotFound {
		return "The configured hostname was not found in DNS."
	}
	return "DNS lookup failed."
}

func describeTLSProbeFailure(err error) string {
	if err == nil {
		return "TLS verification did not complete."
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return "The server certificate does not match the configured hostname."
	}
	var authorityError x509.UnknownAuthorityError
	if errors.As(err, &authorityError) {
		return "The server certificate chain is not trusted by this host."
	}
	var invalidCertificate x509.CertificateInvalidError
	if errors.As(err, &invalidCertificate) {
		return "The server certificate is expired, not yet valid, or otherwise invalid."
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "TCP or TLS verification timed out."
	}
	return "TCP connection or TLS certificate verification failed."
}

func canonicalNetworkAddress(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.String()
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.String()
	}
	return ""
}

func readResolverNameservers() ([]string, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxResolverBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read resolver file: %w", err)
	}
	if len(data) > maxResolverBytes {
		return nil, fmt.Errorf("resolver file exceeds %d bytes", maxResolverBytes)
	}

	seen := make(map[netip.Addr]struct{})
	var nameservers []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		fields := strings.Fields(strings.SplitN(scanner.Text(), "#", 2)[0])
		if len(fields) != 2 || fields[0] != "nameserver" {
			continue
		}
		address, parseErr := netip.ParseAddr(fields[1])
		if parseErr != nil {
			continue
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		nameservers = append(nameservers, address.String())
		if len(nameservers) == 16 {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan resolver file: %w", err)
	}
	return nameservers, nil
}

func (m model) networkDetail() string {
	lines := []string{titleStyle.Render("Network and certificates"),
		"Read-only local and saved-endpoint diagnostics.",
		"Checks run from this TUI process; in Compose, that means the application container's network namespace.", ""}
	if m.statusError != "" {
		lines = append(lines, badStyle.Render("Saved deployment configuration unavailable."), m.statusError)
	} else if m.status != nil {
		lines = append(lines,
			fmt.Sprintf("Configured scope: %s", m.status.Configuration.Network.Scope),
			fmt.Sprintf("Configured authority port: %d", m.status.Configuration.Network.AuthorityPort))
		if m.status.Configuration.Network.BindAddress != "" {
			lines = append(lines, fmt.Sprintf("Configured bind address: %s", m.status.Configuration.Network.BindAddress))
		}
		if m.status.Configuration.Network.ClientHostname != "" {
			lines = append(lines, fmt.Sprintf("Manager client hostname: %s", m.status.Configuration.Network.ClientHostname))
		}
		if m.status.Configuration.Network.Scope == "loopback_development" {
			lines = append(lines, "Development mode exposes the authority only on loopback; remote Manager access is disabled.")
		} else if m.status.Configuration.Network.Scope == "lan" || m.status.Configuration.Network.Scope == "private_dns" {
			if m.status.Configuration.Network.Scope == "private_dns" {
				lines = append(lines, "Private DNS mode uses the configured private address and required hostname over HTTPS. DNS, firewall, proxy, CA trust, and certificate renewal remain operator-managed.")
			} else {
				lines = append(lines, "LAN mode uses HTTPS and the v2 API on the configured private address. DNS, firewall, proxy, and client trust setup remain operator-managed.")
			}
			if m.doctor == nil || m.doctor.Preflight == nil ||
				m.doctor.Preflight.Configuration.Network != m.status.Configuration.Network {
				lines = append(lines, "Last validated TLS certificate-chain fingerprint: unavailable for the saved network configuration.")
			} else {
				if digest := m.doctor.Preflight.TLSCertificateSHA256; len(digest) == 64 && isLowerHex(digest) {
					lines = append(lines, "Last preflight TLS certificate-chain SHA-256: "+digest)
				} else {
					lines = append(lines, "Last preflight did not return a validated TLS certificate-chain fingerprint for this configuration.")
				}
				if m.doctor.Preflight.TLSSubjectNameVerified {
					lines = append(lines, "Last preflight verified the leaf certificate SAN for the configured Manager endpoint.")
				} else {
					lines = append(lines, "Last preflight did not report a verified certificate SAN for this configuration.")
				}
			}
		}
	}
	if m.networkLoading {
		lines = append(lines, "", mutedStyle.Render("Reading local interfaces and resolver configuration."))
	} else if m.networkError != "" {
		lines = append(lines, "", badStyle.Render("Local network diagnostics failed."), m.networkError)
	} else if m.network == nil {
		lines = append(lines, "", "Press d to inspect local interfaces and resolver configuration.")
	} else {
		lines = append(lines, "", fmt.Sprintf("Captured: %s", m.network.capturedAt.Format(time.RFC3339)))
		if len(m.network.interfaces) == 0 {
			lines = append(lines, "No interface addresses were found.")
		}
		lines = append(lines, fmt.Sprintf("Found %d local address(es).", m.network.addressCount))
		shownInterfaces := 0
		shownAddresses := 0
		omittedAddresses := false
		for _, iface := range m.network.interfaces {
			if shownInterfaces >= maxDisplayedInterfaces || shownAddresses >= maxDisplayedAddresses {
				omittedAddresses = true
				break
			}
			state := "down"
			if iface.up {
				state = "up"
			}
			lines = append(lines, fmt.Sprintf("%s (%s)", strconv.QuoteToASCII(iface.name), state))
			for _, address := range iface.address {
				if shownAddresses >= maxDisplayedAddresses {
					omittedAddresses = true
					break
				}
				lines = append(lines, "  "+address)
				shownAddresses++
			}
			shownInterfaces++
		}
		if omittedAddresses || shownAddresses < m.network.addressCount {
			lines = append(lines, "Additional interfaces or addresses omitted from this view.")
		}
		if m.network.resolverInspected {
			if len(m.network.nameservers) == 0 {
				lines = append(lines, "Resolver nameservers: none found")
			} else {
				lines = append(lines, "Resolver nameservers: "+strings.Join(m.network.nameservers, ", "))
			}
		}
		for _, warning := range m.network.warnings {
			lines = append(lines, mutedStyle.Render("Warning: "+warning))
		}
		if m.network.endpointProbe != nil {
			probe := m.network.endpointProbe
			lines = append(lines, "", "Configured endpoint probe")
			if probe.target != "" {
				lines = append(lines, "Target: "+probe.target)
			}
			if probe.dnsStatus != "" {
				lines = append(lines, "DNS: "+probe.dnsStatus)
			}
			if len(probe.resolvedAddresses) > 0 {
				lines = append(lines, "Resolved addresses: "+strings.Join(probe.resolvedAddresses, ", "))
			}
			if probe.ignoredAddresses > 0 {
				lines = append(lines, fmt.Sprintf(
					"Ignored %d DNS address(es) outside private ranges.", probe.ignoredAddresses))
			}
			if probe.omittedAddresses > 0 {
				lines = append(lines, fmt.Sprintf(
					"Did not probe %d additional private address(es); the display is capped at %d.",
					probe.omittedAddresses, maxProbeAddresses))
			}
			if probe.connectedAddress != "" {
				lines = append(lines, "Connected address: "+probe.connectedAddress)
			}
			lines = append(lines, "TLS: "+probe.tlsStatus)
			if probe.tlsFingerprint != "" {
				lines = append(lines,
					fmt.Sprintf("Verified TLS version: %s", probe.tlsVersion),
					"Verified leaf certificate SHA-256: "+probe.tlsFingerprint)
			}
		}
	}
	lines = append(lines, "", mutedStyle.Render(
		"For LAN and private DNS modes, refresh queries DNS and performs a certificate-verified TLS handshake to the saved endpoint; it sends no credentials. It does not inspect firewall rules or public routing."))
	lines = append(lines, "Press d to refresh local details and the saved endpoint probe or r to refresh all status.")
	return strings.Join(lines, "\n")
}

func appendBoundedWarning(warnings []string, warning string) []string {
	if len(warnings) < maxNetworkWarnings-1 {
		return append(warnings, warning)
	}
	if len(warnings) == maxNetworkWarnings-1 {
		return append(warnings, "Additional diagnostic warnings were omitted.")
	}
	if len(warnings) >= maxNetworkWarnings {
		return warnings
	}
	return warnings
}
