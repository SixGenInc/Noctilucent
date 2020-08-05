package tls

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// https://tools.ietf.org/html/draft-ietf-tls-esni-01
const esniKeysVersionDraft01 uint16 = 0xff01

const extensionEncryptedServerName uint16 = 0xffce

const esniNonceLength = 16

// ESNIKeys structure that is exposed through DNS.
type ESNIKeys struct {
	version  uint16
	checksum [4]uint8
	// (Draft -03 introduces "public_name" here)
	keys         []keyShare // 16-bit vector length
	cipherSuites []uint16   // 16-bit vector length
	paddedLength uint16
	notBefore    uint64
	notAfter     uint64
	extensions   []byte // 16-bit vector length. No extensions are defined in draft -01
}

// Like cryptobyte.ReadUint16LengthPrefixed, but accepts a []byte output.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

func readUint64(s *cryptobyte.String, out *uint64) bool {
	var high, low uint32
	if !s.ReadUint32(&high) || !s.ReadUint32(&low) {
		return false
	}
	*out = uint64(high)<<32 | uint64(low)
	return true
}

func addUint64(b *cryptobyte.Builder, v uint64) {
	b.AddUint32(uint32(v >> 32))
	b.AddUint32(uint32(v))
}

// Parses the raw ESNIKeys structure (not base64-encoded). If obtained from DNS,
// then it must have used a secure transport (DoH, DoT).
// Returns a ESNIKeys structure if parsing was successful and nil otherwise
// (unknown version, bad encoding, invalid checksum, etc.)
func ParseESNIKeys(data []byte) (*ESNIKeys, error) {
	k := &ESNIKeys{}
	input := cryptobyte.String(data)
	var keyShares, cipherSuites, extensions cryptobyte.String
	if !input.ReadUint16(&k.version) ||
		k.version != esniKeysVersionDraft01 {
		return nil, errors.New("Invalid version")
	}
	if !input.CopyBytes(k.checksum[:]) {
		return nil, errors.New("Invalid format")
	}

	// Verify checksum: SHA256(ESNIKeys)[:4] with checksum = 0
	hash := sha256.New()
	hash.Write(data[:2]) // version
	hash.Write([]byte{0, 0, 0, 0})
	hash.Write(data[6:]) // fields after checksum
	actualChecksum := hash.Sum(nil)[:4]
	if subtle.ConstantTimeCompare(k.checksum[:], actualChecksum) != 1 {
		return nil, errors.New("Bad checksum")
	}

	if !input.ReadUint16LengthPrefixed(&keyShares) ||
		len(keyShares) == 0 ||
		!input.ReadUint16LengthPrefixed(&cipherSuites) ||
		len(cipherSuites) == 0 ||
		!input.ReadUint16(&k.paddedLength) ||
		!readUint64(&input, &k.notBefore) ||
		!readUint64(&input, &k.notAfter) ||
		!input.ReadUint16LengthPrefixed(&extensions) ||
		!input.Empty() {
		return nil, errors.New("Invalid format")
	}

	for !keyShares.Empty() {
		var ks keyShare
		if !keyShares.ReadUint16((*uint16)(&ks.group)) ||
			!readUint16LengthPrefixed(&keyShares, &ks.data) ||
			len(ks.data) == 0 {
			return nil, errors.New("Invalid format")
		}
		k.keys = append(k.keys, ks)
	}
	for !cipherSuites.Empty() {
		var cipherSuite uint16
		if !cipherSuites.ReadUint16(&cipherSuite) {
			return nil, errors.New("Invalid format")
		}
		k.cipherSuites = append(k.cipherSuites, cipherSuite)
	}
	// Draft -01 does not have any extensions, fail if there are any.
	if !extensions.Empty() {
		return nil, errors.New("Extensions are not supported")
	}
	return k, nil
}

func (k *ESNIKeys) serialize() []byte {
	var b cryptobyte.Builder
	b.AddUint16(k.version)
	b.AddBytes(k.checksum[:])
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, ks := range k.keys {
			b.AddUint16(uint16(ks.group))
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(ks.data)
			})
		}
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, cs := range k.cipherSuites {
			b.AddUint16(cs)
		}
	})
	b.AddUint16(k.paddedLength)
	addUint64(&b, k.notBefore)
	addUint64(&b, k.notAfter)
	// No extensions are defined in the initial draft.
	b.AddUint16(0)
	// Should always succeed as we use simple types only.
	return b.BytesOrPanic()
}

// Returns true if the client can still use this key.
func (k *ESNIKeys) isValid(now time.Time) bool {
	nowUnix := uint64(now.Unix())
	return k.notBefore <= nowUnix && nowUnix <= k.notAfter
}

// Computes a record digest for the given hash algorithm.
func (k *ESNIKeys) recordDigest(hash crypto.Hash) []byte {
	h := hash.New()
	h.Write(k.serialize())
	return h.Sum(nil)
}

func (k *ESNIKeys) createPaddedServerNameList(serverName string) ([]byte, error) {
	if len(serverName) == 0 {
		return nil, errors.New("ServerName must be set")
	}
	// https://tools.ietf.org/html/rfc6066#section-3
	//
	// struct {
	//     NameType name_type;
	//     select (name_type) {
	//         case host_name: HostName;
	//     } name;
	// } ServerName;
	//
	// enum {
	//     host_name(0), (255)
	// } NameType;
	//
	// opaque HostName<1..2^16-1>;
	//
	// struct {
	//     ServerName server_name_list<1..2^16-1>
	// } ServerNameList;
	// TODO use NewFixedBuilder when CL 148882 is imported.
	b := cryptobyte.NewBuilder(make([]byte, 0, k.paddedLength))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // NameType: host_name
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(serverName))
		})
	})
	serverNameList, err := b.Bytes()
	if err != nil || len(serverNameList) > int(k.paddedLength) {
		// The client MUST NOT use ESNI when the name length is too long
		return nil, errors.New("ServerName is too long")
	}
	// Append zeroes as padding (if any).
	serverNameList = serverNameList[:k.paddedLength]
	return serverNameList, nil
}

type clientEncryptedSNI struct {
	suite        uint16   // CipherSuite
	keyShare     keyShare // KeyShareEntry
	recordDigest []byte
	encryptedSni []byte
}

// pickCipherSuite selects a supported cipher suite or returns nil if no mutual
// cipher suite is supported.
func (k *ESNIKeys) pickCipherSuite() *cipherSuite {
	for _, availCipher := range k.cipherSuites {
		for _, supportedCipher := range cipherSuites {
			if supportedCipher.flags&suiteTLS13 == 0 {
				continue
			}
			if supportedCipher.id == availCipher {
				return supportedCipher
			}
		}
	}
	return nil
}

func (k *ESNIKeys) pickKeyShare() keyShare {
	for _, availKeyShare := range k.keys {
		switch availKeyShare.group {
		case CurveP256, CurveP384, CurveP521, X25519:
			return availKeyShare
		}
	}
	return keyShare{}
}

func pickEsniKex(curveId CurveID) kex {
	switch curveId {
	case CurveP256:
		return &kexNIST{}
	case CurveP384:
		return &kexNIST{}
	case CurveP521:
		return &kexNIST{}
	case X25519:
		return &kexX25519{}
	default:
		return nil
	}
}

func serializeKeyShares(keyShares []keyShare) []byte {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, ks := range keyShares {
			b.AddUint16(uint16(ks.group))
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(ks.data)
			})
		}
	})
	return b.BytesOrPanic()
}

func (k *ESNIKeys) makeClientHelloExtension(rand io.Reader, serverName string, clientHelloRandom []byte, clientHelloKeyShares []keyShare) ([]byte, *clientEncryptedSNI, error) {
	suite := k.pickCipherSuite()
	if suite == nil {
		return nil, nil, errors.New("Unsupported cipher suite")
	}
	serverKS := k.pickKeyShare()
	if serverKS.group == 0 {
		return nil, nil, errors.New("Unsupported key shares")
	}

	// Prepare plaintext ESNI contents.
	paddedSNI, err := k.createPaddedServerNameList(serverName)
	if paddedSNI == nil {
		// Name is empty or too long.
		return nil, nil, err
	}
	innerESNI := make([]byte, esniNonceLength+len(paddedSNI))
	esniNonce := innerESNI[:esniNonceLength]
	if _, err := io.ReadFull(rand, esniNonce); err != nil {
		return nil, nil, err
	}
	copy(innerESNI[esniNonceLength:], paddedSNI)

	// Derive key using a new ephemeral key and the semi-static key provided
	// by the server.
	kex := pickEsniKex(serverKS.group)
	if kex == nil {
		return nil, nil, errors.New("Unsupported curve")
	}
	dhSharedSecret, clientKS, err := kex.keyAgreementServer(rand, serverKS)
	if err != nil {
		return nil, nil, err
	}
	recordDigest := k.recordDigest(hashForSuite(suite))
	aead := k.aeadForESNI(suite, recordDigest, clientHelloRandom, clientKS, dhSharedSecret)
	aad := serializeKeyShares(clientHelloKeyShares)
	// A fixed nonce was provided before, do not provide XOR mask since it
	// is used only once.
	esni := aead.Seal(nil, nil, innerESNI, aad)

	clientESNI := &clientEncryptedSNI{
		suite:        suite.id,
		keyShare:     clientKS,
		recordDigest: recordDigest,
		encryptedSni: esni,
	}
	return esniNonce, clientESNI, nil
}

func (clientESNI *clientEncryptedSNI) marshal() []byte {
	var b cryptobyte.Builder
	b.AddUint16(clientESNI.suite)
	b.AddUint16(uint16(clientESNI.keyShare.group))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(clientESNI.keyShare.data)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(clientESNI.recordDigest)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(clientESNI.encryptedSni)
	})
	return b.BytesOrPanic()
}

func (clientESNI *clientEncryptedSNI) unmarshal(data []byte) bool {
	input := cryptobyte.String(data)
	if !input.ReadUint16((*uint16)(&clientESNI.suite)) ||
		!input.ReadUint16((*uint16)(&clientESNI.keyShare.group)) ||
		!readUint16LengthPrefixed(&input, &clientESNI.keyShare.data) ||
		!readUint16LengthPrefixed(&input, &clientESNI.recordDigest) ||
		!readUint16LengthPrefixed(&input, &clientESNI.encryptedSni) ||
		!input.Empty() {
		return false
	}
	return true
}

// processClientESNIForServer processes the ESNI extension sent by the client.
// On success, it returns the nonce, decrypted server name, alertSuccess and no
// error. On failure, it will return the alert code and error description.
func (clientESNI *clientEncryptedSNI) processClientESNIForServer(config *Config, clientHelloRandom []byte, clientHelloKeyShares []keyShare) ([]byte, string, alert, error) {
	if config.GetServerESNIKeys == nil {
		return nil, "", alertIllegalParameter, fmt.Errorf("ESNI support is not enabled")
	}
	// TODO check validity of esniKeys or document that GetServerESNIKeys should check this
	esniKeys, serverPrivateKey, err := config.GetServerESNIKeys(clientESNI.recordDigest)
	if err != nil {
		return nil, "", alertIllegalParameter, fmt.Errorf("tls: unable to find ESNIKeys for server: %s", err)
	}
	if esniKeys == nil || len(serverPrivateKey) == 0 {
		return nil, "", alertInternalError, errors.New("tls: missing ESNIKeys and private key")
	}
	suite := mutualCipherSuite(esniKeys.cipherSuites, clientESNI.suite)
	if suite == nil {
		return nil, "", alertIllegalParameter, fmt.Errorf("tls: forbidden cipher suite for ESNI: %#x", clientESNI.suite)
	}
	clientKS := clientESNI.keyShare
	kex := pickEsniKex(clientKS.group)
	if kex == nil {
		return nil, "", alertIllegalParameter, fmt.Errorf("tls: forbidden key share for ESNI: %#x", clientESNI.keyShare.group)
	}
	// Sanity check the public ESNIKeys value from GetServerESNIKeys against
	// those included in the Client Hello.
	recordDigest := esniKeys.recordDigest(hashForSuite(suite))
	if !bytes.Equal(recordDigest, clientESNI.recordDigest) {
		return nil, "", alertInternalError, fmt.Errorf("tls: GetServerESNIKeys keys do not match the expected record_digest")
	}

	// Compute secrets and decrypt ESNI. keyAgreementClient is used since
	// we (the server) were the first to provide a semi-static ESNI key to
	// the peer.
	dhSharedSecret, err := kex.keyAgreementClient(clientKS, serverPrivateKey)
	if err != nil {
		return nil, "", alertInternalError, err
	}
	aead := esniKeys.aeadForESNI(suite, recordDigest, clientHelloRandom, clientKS, dhSharedSecret)
	aad := serializeKeyShares(clientHelloKeyShares)
	// A fixed nonce was provided before, do not provide XOR mask since it
	// is used only once.
	innerESNI, err := aead.Open(nil, nil, clientESNI.encryptedSni, aad)
	if err != nil {
		return nil, "", alertDecryptError, fmt.Errorf("tls: decryption error in ESNI: %s", err)
	}
	if len(innerESNI) != esniNonceLength+int(esniKeys.paddedLength) {
		return nil, "", alertIllegalParameter, errors.New("tls: bad ESNI padded length")
	}

	esniNonce := innerESNI[:esniNonceLength]
	serverName, ok := parseRealSNI(innerESNI[esniNonceLength:])
	if !ok {
		return nil, "", alertIllegalParameter, errors.New("tls: bad ESNI name")
	}
	return esniNonce, serverName, alertSuccess, nil
}

func parseRealSNI(data []byte) (string, bool) {
	input := cryptobyte.String(data)
	var serverNameList cryptobyte.String
	if !input.ReadUint16LengthPrefixed(&serverNameList) {
		return "", false
	}
	// TODO padding check

	var serverName string
	for !serverNameList.Empty() {
		var nameType uint8
		var name []byte
		if !serverNameList.ReadUint8(&nameType) ||
			!readUint16LengthPrefixed(&serverNameList, &name) {
			return "", false
		}
		if nameType == 0 {
			serverName = string(name)
		}
	}
	if serverName == "" {
		return "", false
	}
	// An SNI value may not include a trailing dot. See
	// https://tools.ietf.org/html/rfc6066#section-3
	if strings.HasSuffix(serverName, ".") {
		return "", false
	}
	return serverName, true
}

// Returns an AEAD for one encryption/decryption operation.
func (k *ESNIKeys) aeadForESNI(suite *cipherSuite, recordDigest, clientHelloRandom []byte, clientKS keyShare, dhSharedSecret []byte) cipher.AEAD {
	hash := hashForSuite(suite)
	hashOfESNIContents := hash.New()
	hashOfESNIContents.Write([]byte{
		byte(len(recordDigest) >> 8),
		byte(len(recordDigest)),
	})
	hashOfESNIContents.Write(recordDigest)
	hashOfESNIContents.Write([]byte{
		byte(clientKS.group >> 8),
		byte(clientKS.group),
		byte(len(clientKS.data) >> 8),
		byte(len(clientKS.data)),
	})
	hashOfESNIContents.Write(clientKS.data)
	hashOfESNIContents.Write(clientHelloRandom[:])
	contextHash := hashOfESNIContents.Sum(nil)

	zx := hkdfExtract(hash, dhSharedSecret, nil)
	key := hkdfExpandLabel(hash, zx, contextHash, "esni key", suite.keyLen)
	iv := hkdfExpandLabel(hash, zx, contextHash, "esni iv", suite.ivLen)
	return suite.aead(key, iv)
}
