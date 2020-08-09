package client

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type WSOverTLS struct {
	*common.WebSocketConn
	cdnDomainPort  string
	host           string
	ESNIServerName string
	PreserveSNI    bool
	esniKeys       string
}

func (ws *WSOverTLS) Handshake(rawConn net.Conn, authInfo AuthInfo) (sessionKey [32]byte, err error) {
	// utlsConfig := &utls.Config{
	// 	ServerName:         authInfo.MockDomain,
	// 	InsecureSkipVerify: true,
	// }
	// uconn := utls.UClient(rawConn, utlsConfig, utls.HelloChrome_Auto)
	// err = uconn.Handshake()
	// if err != nil {
	// 	return
	// }

	// == Start Noctilucent addition ==
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13, // Force 1.3
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		ServerName:         ws.host,
		PreserveSNI:        ws.PreserveSNI,
		ESNIServerName:     ws.ESNIServerName,
	}

	var esniKeysBytes []byte
	// Try to get embedded key bytes from config
	if len(ws.esniKeys) != 0 {
		esniKeysBytes, err = base64.StdEncoding.DecodeString(ws.esniKeys)
		if err != nil {
			log.Fatalf("[E] Failed to parse esniKeys from config: %s", err)
		}
	}
	// Still no key bytes
	if len(esniKeysBytes) == 0 {
		esniKeysBytes, err = QueryESNIKeysForHostDoH("cloudflare.com", true)
		// Try to query ESNI keys via DoH, then DoT, and finally standard DNS
		if err != nil {
			log.Infof("[E] Failed to retrieve ESNI keys for host via DoH: %s", err)
			esniKeysBytes, err = QueryESNIKeysForHostDoT(ws.host)
			if err != nil {
				log.Printf("[E] Failed to retrieve ESNI keys for host via TLS: %s", err)
				esniTxts, err := net.LookupTXT(ws.host)
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
		log.Debugf("[+] Successfully queried _esni TXT record for host: %s", ws.host)
	}
	tlsConfig.ClientESNIKeys, err = tls.ParseESNIKeys(esniKeysBytes)
	if tlsConfig.ClientESNIKeys == nil {
		log.Fatalf("[E] Failed to process ESNI keys for host: %s", err)
	}
	// == End Noctilucent addition ==
	log.Debugf("[+] Connecting to https://" + ws.host)
	con, err := tls.Dial("tcp", ws.cdnDomainPort, tlsConfig)
	if err != nil {
		log.Errorf("[E] handshake failed: %v\n\n", err)
	}
	log.Debugf("[+] TLS handshake complete")

	u, err := url.Parse("ws://" + ws.cdnDomainPort)
	if err != nil {
		return sessionKey, fmt.Errorf("failed to parse ws url: %v", err)
	}

	payload, sharedSecret := makeAuthenticationPayload(authInfo)
	header := http.Header{}
	header.Add("hidden", base64.StdEncoding.EncodeToString(append(payload.randPubKey[:], payload.ciphertextWithTag[:]...)))
	// == Start Noctilucent addition ==
	header.Add("Host", ws.ESNIServerName)
	// == End Noctilucent addition ==
	c, _, err := websocket.NewClient(con, u, header, 16480, 16480)
	if err != nil {
		return sessionKey, fmt.Errorf("failed to handshake: %v", err)
	}

	ws.WebSocketConn = &common.WebSocketConn{Conn: c}

	buf := make([]byte, 128)
	n, err := ws.Read(buf)
	if err != nil {
		return sessionKey, fmt.Errorf("failed to read reply: %v", err)
	}

	if n != 60 {
		return sessionKey, errors.New("reply must be 60 bytes")
	}

	reply := buf[:60]
	sessionKeySlice, err := common.AESGCMDecrypt(reply[:12], sharedSecret[:], reply[12:])
	if err != nil {
		return
	}
	copy(sessionKey[:], sessionKeySlice)

	return
}
