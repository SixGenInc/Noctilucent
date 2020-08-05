package tls

import (
	"encoding/base64"
	"fmt"
	"testing"
)

// dig _esni.cloudflare.com TXT +short
const esniTxtRecord = "/wE7+NS+ACQAHQAgxTKiPqR+6KrU1WMBf21UbzibTZ3kOW2wV8aSohULfzQAAhMBAQQAAAAAXKm8EAAAAABcsaUQAAA="

var esniKeysData []byte

func init() {
	d, err := base64.StdEncoding.DecodeString(esniTxtRecord)
	if err != nil {
		panic(fmt.Sprintf("Bad base64-encoded ESNI record: %s", err))
	}
	esniKeysData = d
}

func TestParseESNIKeysCorruptChecksum(t *testing.T) {
	d := make([]byte, len(esniKeysData))
	copy(d, esniKeysData)
	d[2] ^= 0xff // corrupt checksum
	k, err := ParseESNIKeys(d)
	if k != nil {
		t.Error("Bad checksum, expected failure!")
	}
	if err.Error() != "Bad checksum" {
		t.Errorf("Expected checksum error, got: %s", err)
	}
}

func TestParseESNIKeys(t *testing.T) {
	k, err := ParseESNIKeys(esniKeysData)
	if k == nil || err != nil {
		t.Errorf("Unable to parse ESNI record: %s", err)
	}
	if k.version != 0xff01 {
		t.Errorf("Unexpected version: %#04x", k.version)
	}
	if len(k.keys) != 1 || k.keys[0].group != X25519 || len(k.keys[0].data) != 32 {
		t.Errorf("Unexpected keyShare: %v", k.keys)
	}
	if len(k.cipherSuites) != 1 || k.cipherSuites[0] != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Unexpected cipher suites: %v", k.cipherSuites)
	}
	if k.paddedLength != 260 {
		t.Errorf("Unexpected paddedLength: %d", k.paddedLength)
	}
	if k.notBefore != 1554627600 {
		t.Errorf("Unexpected notBefore: %d", k.notBefore)
	}
	if k.notAfter != 1555146000 {
		t.Errorf("Unexpected notAfter: %d", k.notAfter)
	}
	if len(k.extensions) != 0 {
		t.Errorf("Unexpected extensions: %v", k.extensions)
	}
}
