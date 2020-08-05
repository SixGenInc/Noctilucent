package client

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

func makeDoTQuery(dnsName string) ([]byte, error) {
	query := dnsmessage.Message{
		Header: dnsmessage.Header{
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(dnsName),
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	req, err := query.Pack()
	if err != nil {
		return nil, err
	}
	l := len(req)
	req = append([]byte{
		uint8(l >> 8),
		uint8(l),
	}, req...)
	return req, nil
}

func parseTXTResponse(buf []byte, wantName string) (string, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(buf)
	if err != nil {
		return "", err
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return "", fmt.Errorf("DNS query failed, rcode=%s", hdr.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", err
	}
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return "", err
		}
		if h.Type != dnsmessage.TypeTXT || h.Class != dnsmessage.ClassINET {
			continue
		}
		if !strings.EqualFold(h.Name.String(), wantName) {
			if err := p.SkipAnswer(); err != nil {
				return "", err
			}
		}
		r, err := p.TXTResource()
		if err != nil {
			return "", err
		}
		return r.TXT[0], nil
	}
	return "", errors.New("No TXT record found")
}

func QueryESNIKeysForHostDoT(hostname string) ([]byte, error) {
	esniDNSName := "_esni." + hostname + "."
	query, err := makeDoTQuery(esniDNSName)
	if err != nil {
		return nil, fmt.Errorf("Building DNS query failed: %s", err)
	}

	c, err := tls.Dial("tcp", "1.1.1.1:853", &tls.Config{})
	if err != nil {
		return nil, err
	}
	defer c.Close()

	// Send DNS query
	n, err := c.Write(query)
	if err != nil || n != len(query) {
		return nil, fmt.Errorf("Failed to write query: %s", err)
	}

	// Read DNS response
	buf := make([]byte, 4096)
	n, err = c.Read(buf)
	if n < 2 && err != nil {
		return nil, fmt.Errorf("Cannot read response: %s", err)
	}
	txt, err := parseTXTResponse(buf[2:n], esniDNSName)
	if err != nil {
		return nil, fmt.Errorf("Cannot process TXT record: %s", err)
	}
	return base64.StdEncoding.DecodeString(txt)
}
