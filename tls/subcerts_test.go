// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"
)

// A PEM-encoded "delegation certificate", an X.509 certificate with the
// DelegationUsage extension. The extension is defined in
// specified in https://tools.ietf.org/html/draft-ietf-tls-subcerts-02.
const DcCertWithDelegationUsage = `-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIQXXtl0v50W2OadoW0QwLUlzAKBggqhkjOPQQDAjAUMRIw
EAYDVQQKEwlBY21lIEluYy4wHhcNMTgwNzMwMjAxMTE5WhcNMTgwODA2MjAxMTE5
WjAUMRIwEAYDVQQKEwlBY21lIEluYy4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATcQuuaUNJ3kqKGs4DBdJVd7zWzyGANT4uBNGVkZ2cgaDsdFnx99fGibfgoWer8
HLt9Z+S6Hs+8bDPBHNgTR/Lfo1UwUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
CgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAPBgNVHREECDAGhwR/AAABMA0GCSsG
AQQBgtpLLAQAMAoGCCqGSM49BAMCA0cAMEQCIEMdIkwwmzQAJ6RSDT3wcrsySx2B
5Lvx5HGzc43Fgu9eAiAi4sFXnizFBVUL43qXZBq4ARw17o0JW3/7eec1xttQhw==
-----END CERTIFICATE-----
`

// The PEM-encoded "delegation key", the secret key associated with the
// delegation certificate. This is a key for ECDSA with P256 and SHA256.
const DcKeyWithDelegationUsage = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAS/pGktmxK1hlt3gF4N2nkMrJnoZihvOO63nnNcxXQroAoGCCqGSM49
AwEHoUQDQgAE3ELrmlDSd5KihrOAwXSVXe81s8hgDU+LgTRlZGdnIGg7HRZ8ffXx
om34KFnq/By7fWfkuh7PvGwzwRzYE0fy3w==
-----END EC PRIVATE KEY-----
`

// A certificate without the DelegationUsage extension.
const DcCertWithoutDelegationUsage = `-----BEGIN CERTIFICATE-----
MIIBajCCAQ+gAwIBAgIRAMUg/VFqJaWWJwZ9iHoMjqIwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEChMHQWNtZSBDbzAeFw0xODA3MzAyMDExMTlaFw0xOTA3MzAyMDExMTla
MBIxEDAOBgNVBAoTB0FjbWUgQ28wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATA
n+oeWSvSNHhEskSRgkkerCQDoV/NA+r3S5AtCOFT5AYLt8xltSTWerFI/YlZLIcL
xlJPT7T+XpBnfS6xaAuxo0YwRDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYI
KwYBBQUHAwEwDAYDVR0TAQH/BAIwADAPBgNVHREECDAGhwR/AAABMAoGCCqGSM49
BAMCA0kAMEYCIQCFGWnoJmwH1rxNCKBJWVDBKDTSsYhySRk4h9RPyR8bUwIhAJxc
KFyrowMTan791RJnyANH/4uYhmvkfhfrFGSTXUli
-----END CERTIFICATE-----
`

// The secret key associatted with DcCertWithoutDelegationUsage.
const DcKeyWithoutDelegationUsage = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEP82pOhzx0tKkky9t0OmUo9MHgmfdAHxDN2cHmWGqOhoAoGCCqGSM49
AwEHoUQDQgAEwJ/qHlkr0jR4RLJEkYJJHqwkA6FfzQPq90uQLQjhU+QGC7fMZbUk
1nqxSP2JWSyHC8ZST0+0/l6QZ30usWgLsQ==
-----END EC PRIVATE KEY-----
`

// dcTestDC stores delegated credentials and their secret keys.
type dcTestDC struct {
	Name       string
	Version    int
	Scheme     int
	DC         []byte
	PrivateKey []byte
}

// Use with maxVersion == VersionTLS13.
const DcTestDataTLS13PEM = `-----BEGIN DC TEST DATA-----
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
jreml8HfVQ==
-----END DC TEST DATA-----`

// Parses the input PEM block containing the test DCs.
func dcLoadTestData(in []byte, out *[]dcTestDC) error {
	block, _ := pem.Decode(in)
	if block == nil {
		return errors.New("failed to decode DC tests PEM block")
	}

	// Parse the DER-encoded test DCs.
	_, err := asn1.Unmarshal(block.Bytes, out)
	if err != nil {
		return errors.New("failed to unmarshal DC test ASN.1 data")
	}

	// Check that the test data is for the right version. This should be
	// maxVersion, defined in common.go.
	for _, test := range *out {
		dc, err := unmarshalDelegatedCredential(test.DC)
		if err != nil {
			return err
		}

		// Sanity check that test version matches the version encoded by the DC.
		testVersion := uint16(test.Version)
		if dc.cred.expectedVersion != testVersion {
			return fmt.Errorf(
				"test version doesn't match credential version: got: 0x0%04x; want: 0x%04x",
				testVersion, dc.cred.expectedVersion)
		}

		// With the exception of "badvers" and "tsl12", all test DCs should have
		// the expected verison.
		if test.Name != "badvers" && test.Name != "tls12" && testVersion != maxVersion {
			return fmt.Errorf(
				"encountered test with wrong version: got: 0x0%04x; want: 0x%04x",
				test.Version, maxVersion)
		}
	}
	return nil
}

var dcTestDCs []dcTestDC
var dcTestConfig *Config
var dcTestDelegationCert Certificate
var dcTestCert Certificate
var dcTestNow time.Time

func init() {
	// Load the DC test data.
	var testData []byte
	if maxVersion != 0x0304 {
		panic(fmt.Errorf("no test data for version %04x", maxVersion))
	}
	testData = []byte(DcTestDataTLS13PEM)

	err := dcLoadTestData(testData, &dcTestDCs)
	if err != nil {
		panic(err)
	}

	// The base configuration for the client and server.
	dcTestConfig = &Config{
		Time: func() time.Time {
			return dcTestNow
		},
		Rand:         zeroSource{},
		Certificates: nil,
		MinVersion:   VersionTLS10,
		MaxVersion:   VersionTLS13,
		CipherSuites: allCipherSuites(),
	}

	// The delegation certificate.
	dcTestDelegationCert, err = X509KeyPair([]byte(DcCertWithDelegationUsage), []byte(DcKeyWithDelegationUsage))
	if err != nil {
		panic(err)
	}
	dcTestDelegationCert.Leaf, err = x509.ParseCertificate(dcTestDelegationCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	// A certificate without the the DelegationUsage extension for X.509.
	dcTestCert, err = X509KeyPair([]byte(DcCertWithoutDelegationUsage), []byte(DcKeyWithoutDelegationUsage))
	if err != nil {
		panic(err)
	}
	dcTestCert.Leaf, err = x509.ParseCertificate(dcTestCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	// For testing purposes, use the point at which the test DCs were generated
	// as the current time.  This is the same as the time at which the
	// delegation certificate was generated.
	dcTestNow = dcTestDelegationCert.Leaf.NotBefore

	// Make these roots of these certificates the client's trusted CAs.
	dcTestConfig.RootCAs = x509.NewCertPool()

	raw := dcTestDelegationCert.Certificate[len(dcTestDelegationCert.Certificate)-1]
	root, err := x509.ParseCertificate(raw)
	if err != nil {
		panic(err)
	}
	dcTestConfig.RootCAs.AddCert(root)

	raw = dcTestCert.Certificate[len(dcTestCert.Certificate)-1]
	root, err = x509.ParseCertificate(raw)
	if err != nil {
		panic(err)
	}
	dcTestConfig.RootCAs.AddCert(root)
}

// Executes the handshake with the given configuration and returns true if the
// delegated credential extension was successfully negotiated.
func testConnWithDC(t *testing.T, clientConfig, serverConfig *Config) (bool, error) {
	ln := newLocalListener(t)
	defer ln.Close()

	// Listen for and serve a single client connection.
	srvCh := make(chan *Conn, 1)
	var serr error
	go func() {
		sconn, err := ln.Accept()
		if err != nil {
			serr = err
			srvCh <- nil
			return
		}
		srv := Server(sconn, serverConfig)
		if err := srv.Handshake(); err != nil {
			serr = fmt.Errorf("handshake: %v", err)
			srvCh <- nil
			return
		}
		srvCh <- srv
	}()

	// Dial the server.
	cli, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		return false, err
	}
	defer cli.Close()

	srv := <-srvCh
	if srv == nil {
		return false, serr
	}

	// Return true if the client's conn.dc structure was instantiated.
	st := cli.ConnectionState()
	return (st.DelegatedCredential != nil), nil
}

// Checks that the client suppports a version >= 1.2 and accepts delegated
// credentials. If so, it returns the delegation certificate; otherwise it
// returns a plain certificate.
func testServerGetCertificate(ch *ClientHelloInfo) (*Certificate, error) {
	versOk := false
	for _, vers := range ch.SupportedVersions {
		versOk = versOk || (vers >= uint16(VersionTLS12))
	}

	if versOk && ch.AcceptsDelegatedCredential {
		return &dcTestDelegationCert, nil
	}
	return &dcTestCert, nil
}

// Various test cases for handshakes involving DCs.
var dcTesters = []struct {
	clientDC         bool
	serverDC         bool
	clientSkipVerify bool
	clientMaxVers    uint16
	serverMaxVers    uint16
	nowOffset        time.Duration
	dcTestName       string
	expectSuccess    bool
	expectDC         bool
	name             string
}{
	{true, true, false, VersionTLS13, VersionTLS13, 0, "tls13p256", true, true, "tls13"},
	{true, true, false, VersionTLS13, VersionTLS13, 0, "tls13p521", true, true, "tls13"},
	{true, false, false, VersionTLS13, VersionTLS13, 0, "tls13p256", true, false, "server no dc"},
	{true, true, false, VersionTLS12, VersionTLS13, 0, "tls13p256", true, false, "client old"},
	{true, true, false, VersionTLS13, VersionTLS12, 0, "tls13p256", true, false, "server old"},
	{true, true, false, VersionTLS13, VersionTLS13, 0, "badkey", false, false, "bad key"},
	{true, true, true, VersionTLS13, VersionTLS13, 0, "badsig", true, true, "bad key, skip verify"},
	{true, true, false, VersionTLS13, VersionTLS13, dcMaxTTL, "tls13", false, false, "expired dc"},
	{true, true, false, VersionTLS13, VersionTLS13, 0, "badvers", false, false, "dc wrong version"},
	{true, true, false, VersionTLS12, VersionTLS12, 0, "tls12", true, false, "tls12"},
}

// Tests the handshake with the delegated credential extension for each test
// case in dcTests.
func TestDCHandshake(t *testing.T) {
	clientConfig := dcTestConfig.Clone()
	serverConfig := dcTestConfig.Clone()
	serverConfig.GetCertificate = testServerGetCertificate

	for i, tester := range dcTesters {
		clientConfig.MaxVersion = tester.clientMaxVers
		serverConfig.MaxVersion = tester.serverMaxVers
		clientConfig.InsecureSkipVerify = tester.clientSkipVerify
		clientConfig.AcceptDelegatedCredential = tester.clientDC
		clientConfig.Time = func() time.Time {
			return dcTestNow.Add(time.Duration(tester.nowOffset))
		}

		if tester.serverDC {
			serverConfig.GetDelegatedCredential = func(
				ch *ClientHelloInfo, vers uint16) ([]byte, crypto.PrivateKey, error) {
				if vers < VersionTLS13 {
					return nil, nil, nil
				}
				for _, test := range dcTestDCs {
					if test.Name == tester.dcTestName {
						sk, err := x509.ParseECPrivateKey(test.PrivateKey)
						if err != nil {
							return nil, nil, err
						}
						return test.DC, sk, nil
					}
				}
				return nil, nil, fmt.Errorf("Test DC with name '%s' not found", tester.dcTestName)
			}
		} else {
			serverConfig.GetDelegatedCredential = nil
		}

		usedDC, err := testConnWithDC(t, clientConfig, serverConfig)
		if err != nil && tester.expectSuccess {
			t.Errorf("test #%d (%s) fails: %s", i+1, tester.name, err)
		} else if err == nil && !tester.expectSuccess {
			t.Errorf("test #%d (%s) succeeds; expected failure", i+1, tester.name)
		}

		if usedDC != tester.expectDC {
			t.Errorf("test #%d (%s) usedDC = %v; expected %v", i+1, tester.name, usedDC, tester.expectDC)
		}
	}
}
