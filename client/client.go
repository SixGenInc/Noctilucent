package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"../websocket"
)

var tlsVersionToName = map[uint16]string{
	tls.VersionTLS10: "1.0",
	tls.VersionTLS11: "1.1",
	tls.VersionTLS12: "1.2",
	tls.VersionTLS13: "1.3",
}

var cipherSuiteIdToName = map[uint16]string{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
}

var namedGroupsToName = map[uint16]string{
	uint16(tls.HybridSIDHp503Curve25519): "X25519-SIDHp503",
	uint16(tls.HybridSIKEp503Curve25519): "X25519-SIKEp503",
	uint16(tls.X25519):                   "X25519",
	uint16(tls.CurveP256):                "P-256",
	uint16(tls.CurveP384):                "P-384",
	uint16(tls.CurveP521):                "P-521",
}

func getIDByName(m map[uint16]string, name string) (uint16, error) {
	for key, value := range m {
		if value == name {
			return key, nil
		}
	}
	return 0, errors.New("Unknown value")
}

var failed uint

type Client struct {
	TLS        tls.Config
	addr       string
	hostHeader string
	URL        string
	UserAgent  string
}

func NewClient(insecureSkipVerify bool, serverName string, preserveSNI bool, ESNIServerName string) *Client {
	var c Client
	c.TLS.InsecureSkipVerify = insecureSkipVerify
	c.TLS.ServerName = serverName
	c.TLS.PreserveSNI = preserveSNI
	c.TLS.ESNIServerName = ESNIServerName
	return &c
}

func (c *Client) setMinMaxTLS(ver uint16) {
	c.TLS.MinVersion = ver
	c.TLS.MaxVersion = ver
}

func (c *Client) run() {
	fmt.Println("[+] Connecting to https://" + c.addr)
	con, err := tls.Dial("tcp", c.addr, &c.TLS)
	if err != nil {
		fmt.Printf("[E] handshake failed: %v\n\n", err)
		failed++
		return
	}
	defer con.Close()
	fmt.Println("[+] TLS handshake complete")

	getRequest := "GET " + c.URL + " HTTP/1.1\r\nHost: " + c.hostHeader +
		"\r\nUser-Agent: " + c.UserAgent + "\r\nAccept: */*\r\n" +
		"Connection: close\r\n\r\n"
	fmt.Println("[+] Sending GET request:", getRequest)
	_, err = con.Write([]byte(getRequest))
	fmt.Println("[+] GET request sent")
	if err != nil {
		fmt.Printf("[E] Write failed: %v\n\n", err)
		failed++
		return
	}

	buf := make([]byte, 1024)
	n, err := con.Read(buf)

	// Read whole response
	//var buf bytes.Buffer
	//io.Copy(&buf, con)
	//n := buf.Len()

	// A non-zero read with EOF is acceptable and occurs when a close_notify
	// is received right after reading data (observed with NSS selfserv).
	if !(n > 0 && err == io.EOF) && err != nil {
		fmt.Printf("[E] Read failed: %v\n\n", err)
		failed++
		return
	}
	fmt.Println("[=] Reponse:")
	s := fmt.Sprintf("%s", buf)
	fmt.Println(s)
	fmt.Printf("[=] TLS %s => Read %d bytes\n", tlsVersionToName[con.ConnectionState().Version], n)
}

func main() {
	var keylogFile, esniKeys, TLSVersion, namedGroups, namedCiphers, serverName, ESNIServerName, HostHeader, TLSHost, URL, UserAgent, esniKeyHost string
	var clientAuth, enableEsni, preserveSNI, insecureSkipVerify, DoHInsecureSkipVerify, useWebsocket bool

	flag.StringVar(&keylogFile, "keylogfile", "", "Secrets will be logged here")
	flag.BoolVar(&clientAuth, "cliauth", false, "Whether to enable client authentication (requires certs and keys to be compiled in)")
	flag.StringVar(&TLSVersion, "TLSVersion", "1.3", "TLS version to use")
	flag.StringVar(&namedGroups, "groups", "X25519:P-256:P-384:P-521", "NamedGroups IDs to use")
	flag.StringVar(&namedCiphers, "ciphers", "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384", "Named cipher IDs to use")
	flag.BoolVar(&enableEsni, "esni", false, "Whether to enable ESNI (using DNS if -esni-keys is not provided)")
	flag.StringVar(&esniKeys, "esni-keys", "", "Enable ESNI, using the base64-encoded ESNIKeys from this file instead of DNS")
	flag.BoolVar(&preserveSNI, "preserveSNI", false, "Whether or not to preserve the *unecrypted* SNI value when using ESNI (useful to fool filters - default false)")
	flag.BoolVar(&insecureSkipVerify, "insecureSkipVerify", true, "Whether to skip verification of the TLS certificate from the server (when fronting this will always be the case)")
	flag.BoolVar(&DoHInsecureSkipVerify, "DoHInsecureSkipVerify", false, "Whether to skip verification of the TLS certificate from the DoH server")
	flag.StringVar(&serverName, "serverName", "", "The string to use in the *unencrypted* SNI header")
	flag.StringVar(&ESNIServerName, "ESNIServerName", "", "The string to use in the *encrypted* SNI header")
	flag.StringVar(&HostHeader, "HostHeader", "", "The string to use in the *encrypted* HTTP GET Host header")
	flag.StringVar(&TLSHost, "TLSHost", "", "The host to initiate the TLS connection with, host:port (default port is 443 if not supplied)")
	flag.BoolVar(&useWebsocket, "useWebsocket", false, "Use websockets to connect to the TLS host (default false)")
	flag.StringVar(&URL, "URL", "/", "The URL to request or connect to if using websockets")
	flag.StringVar(&UserAgent, "UserAgent", "ESNI_FRONT_TEST", "The User-Agent string to use in web requests")
	flag.StringVar(&esniKeyHost, "esniKeyHost", "cloudflare.com", "The host to query for the esni public key")

	flag.Parse()

	if serverName == "" && ESNIServerName == "" {
		fmt.Println("[E] serverName or ESNIServeName must be provided")
		flag.Usage()
		os.Exit(1)
	}

	if TLSHost == "" {
		fmt.Println("[E] TLSHost must be provided")
		flag.Usage()
		os.Exit(1)
	}

	client := NewClient(insecureSkipVerify, serverName, preserveSNI, ESNIServerName)
	client.addr = TLSHost
	if !strings.Contains(client.addr, ":") {
		client.addr += ":443"
	}
	host, _, err := net.SplitHostPort(client.addr)
	if err != nil {
		log.Fatalf("[E] Cannot parse address: %s", err)
	}

	if keylogFile == "" {
		keylogFile = os.Getenv("SSLKEYLOGFILE")
	}
	if keylogFile != "" {
		keylog_writer, err := os.OpenFile(keylogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("[E] Cannot open keylog file: %v", err)
		}
		client.TLS.KeyLogWriter = keylog_writer
		log.Println("[+] Enabled keylog")
	}

	if clientAuth {
		var err error
		client_cert, err := tls.X509KeyPair([]byte(client_crt), []byte(client_key))
		if err != nil {
			panic("[E] Can't load client certificate")
		}

		client.TLS.Certificates = []tls.Certificate{client_cert}
		client.TLS.RootCAs = x509.NewCertPool()
		if !client.TLS.RootCAs.AppendCertsFromPEM([]byte(client_ca)) {
			panic("[E] Can't load client CA cert")
		}
	}

	var esniKeysBytes []byte
	if len(esniKeys) != 0 {
		contents, err := ioutil.ReadFile(esniKeys)
		if err != nil {
			log.Fatalf("[E] Failed to read ESNIKeys: %s", err)
		}
		esniKeysBytes, err = base64.StdEncoding.DecodeString(string(contents))
		if err != nil {
			log.Fatalf("[E] Failed to parse -esni-keys: %s", err)
		}
		enableEsni = true
	} else if enableEsni {
		esniKeysBytes, err = QueryESNIKeysForHostDoH(esniKeyHost, DoHInsecureSkipVerify)
		// Try to query ESNI keys via DoH, then DoT, and finally standard DNS
		if err != nil {
			log.Printf("[E] Failed to retrieve ESNI keys for host via DoH: %s", err)
			esniKeysBytes, err = QueryESNIKeysForHostDoT(esniKeyHost)
			if err != nil {
				log.Printf("[E] Failed to retrieve ESNI keys for host via TLS: %s", err)
				esniTxts, err := net.LookupTXT("_esni." + esniKeyHost)
				if err != nil {
					log.Fatalf("[E] Failed to retrieve ESNI keys for host via standard DNS: %s", err)
				}
				if len(esniTxts) != 1 {
					log.Fatalf("[E] Unexpected number of TXT responses when querying ESNI keys via standard DNS")
				}
				esniKeysBytes, err = base64.StdEncoding.DecodeString(esniTxts[0])
				if err != nil {
					log.Fatalf("[E] Failed to decode TXT response when querying ESNI keys via standard DNS: %s", err)
				}
			}
		}
		fmt.Println("[+] Successfully queried _esni TXT record for host:", host)
	}
	if enableEsni {
		client.TLS.ClientESNIKeys, err = tls.ParseESNIKeys(esniKeysBytes)
		if client.TLS.ClientESNIKeys == nil {
			log.Fatalf("[E] Failed to process ESNI keys for host: %s", err)
		}
	}

	// Set requested DH groups
	client.TLS.CurvePreferences = []tls.CurveID{}
	for _, ng := range strings.Split(namedGroups, ":") {
		id, err := getIDByName(namedGroupsToName, ng)
		if err != nil {
			panic("[E] Wrong group name provided")
		}
		client.TLS.CurvePreferences = append(client.TLS.CurvePreferences, tls.CurveID(id))
	}

	// Perform TLS handshake
	tlsID, err := getIDByName(tlsVersionToName, TLSVersion)
	if err != nil {
		panic("[E] Unknown TLS version")
	}
	client.setMinMaxTLS(tlsID)

	// Offer all ciphers
	for _, cn := range strings.Split(namedCiphers, ":") {
		id, err := getIDByName(cipherSuiteIdToName, cn)
		if err != nil {
			panic("[E] Wrong cipher name provided")
		}
		client.TLS.CipherSuites = append(client.TLS.CipherSuites, id)
	}
	client.hostHeader = HostHeader
	client.URL = URL
	client.UserAgent = UserAgent

	fmt.Printf("[=] TLS %s with %s\n", tlsVersionToName[client.TLS.MinVersion], cipherSuiteIdToName[client.TLS.CipherSuites[0]])
	if client.TLS.ESNIServerName != "" {
		fmt.Println("[=] ESNI host set to:", client.TLS.ESNIServerName)
	} else {
		fmt.Println("[=] ESNI host has not been set")
	}
	if client.TLS.PreserveSNI || client.TLS.ESNIServerName == "" {
		fmt.Println("[=] SNI host set to:", client.TLS.ServerName)
	} else {
		fmt.Println("[=] SNI host has been unset")
	}

	if !useWebsocket {
		client.run()
	} else {

		config, _ := websocket.NewConfigWithHost("wss://"+host+URL, "https://"+host, ESNIServerName)
		config.TlsConfig = &client.TLS
		ws, err := websocket.DialConfig(config)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("[+] Connecting to wss://" + host + URL)
		fmt.Println("[+] TLS handshake complete")

		message := []byte("Hello DEF CON 28!")
		fmt.Printf("[+] Websocket Send: %s\n", message)
		_, err = ws.Write(message)
		if err != nil {
			log.Fatal(err)
		}

		var msg = make([]byte, 512)
		_, err = ws.Read(msg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("[+] Websocket Receive: %s\n", msg)
		return
	}

}

const (
	client_ca = `-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----`
	client_crt = `-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----`
	client_key = `-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----`
)
