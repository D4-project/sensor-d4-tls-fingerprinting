package d4tls

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/D4-project/sensor-d4-tls-fingerprinting/etls"
	"github.com/glaslos/tlsh"
)

var grease = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

type certMapElm struct {
	CertHash string
	*x509.Certificate
}

type sessionRecord struct {
	ServerIP     string
	ServerPort   string
	ClientIP     string
	ClientPort   string
	TLSH         string
	Timestamp    time.Time
	JA3          string
	JA3Digest    string
	JA3S         string
	JA3SDigest   string
	Certificates []certMapElm
}

// TLSSession contains a handshakeRecord that had to be filled during the handshake,
// and a Record that will be at last exported to Json
type TLSSession struct {
	Record          sessionRecord
	handShakeRecord etls.ETLSHandshakeRecord
	stage           int
}

// String returns a string that describes a TLSSession
func (t *TLSSession) String() string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("---------------SESSION START-------------------\n"))
	buf.WriteString(fmt.Sprintf("Time: %v\n", t.Record.Timestamp))
	buf.WriteString(fmt.Sprintf("Client: %v:%v\n", t.Record.ClientIP, t.Record.ClientPort))
	buf.WriteString(fmt.Sprintf("Server: %v:%v\n", t.Record.ServerIP, t.Record.ServerPort))
	buf.WriteString(fmt.Sprintf("TLSH: %q\n", t.Record.TLSH))
	buf.WriteString(fmt.Sprintf("ja3: %q\n", t.Record.JA3))
	buf.WriteString(fmt.Sprintf("ja3 Digest: %q\n", t.Record.JA3Digest))
	buf.WriteString(fmt.Sprintf("ja3s: %q\n", t.Record.JA3S))
	buf.WriteString(fmt.Sprintf("ja3s Digest: %q\n", t.Record.JA3SDigest))
	for _, certMe := range t.Record.Certificates {
		buf.WriteString(fmt.Sprintf("Certificate Issuer: %q\n", certMe.Certificate.Issuer))
		buf.WriteString(fmt.Sprintf("Certificate Subject: %q\n", certMe.Certificate.Subject))
		buf.WriteString(fmt.Sprintf("Certificate is CA: %t\n", certMe.Certificate.IsCA))
		buf.WriteString(fmt.Sprintf("Certificate SHA256: %q\n", certMe.CertHash))
	}
	buf.WriteString(fmt.Sprintf("---------------SESSION  END--------------------\n"))
	return buf.String()
}

// PopulateClientHello takes a pointer to an etls ClientHelloMsg and writes it to the the TLSSession struct
func (t *TLSSession) PopulateClientHello(h *etls.ClientHelloMsg, cip string, sip string, cp string, sp string, ti time.Time) {
	if t.stage < 1 {
		t.Record.ClientIP = cip
		t.Record.ServerIP = sip
		t.Record.ClientPort = cp
		t.Record.ServerPort = sp
		t.Record.Timestamp = ti
		t.handShakeRecord.ETLSHandshakeClientHello = h
		t.stage = 1
	}
}

// PopulateServerHello takes a pointer to an etls ServerHelloMsg and writes it to the TLSSession struct
func (t *TLSSession) PopulateServerHello(h *etls.ServerHelloMsg) {
	if t.stage < 2 {
		t.handShakeRecord.ETLSHandshakeServerHello = h
		t.stage = 2
	}
}

// PopulateCertificate takes a pointer to an etls ServerHelloMsg and writes it to the TLSSession struct
func (t *TLSSession) PopulateCertificate(c *etls.CertificateMsg) {
	if t.stage < 3 {
		t.handShakeRecord.ETLSHandshakeCertificate = c
		for _, asn1Data := range t.handShakeRecord.ETLSHandshakeCertificate.Certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				//return err
			} else {
				h := sha256.New()
				h.Write(cert.Raw)
				t.Record.Certificates = append(t.Record.Certificates, certMapElm{Certificate: cert, CertHash: fmt.Sprintf("%x", h.Sum(nil))})
			}
		}
	}
}

// D4Fingerprinting computes fingerprints doh
func (t *TLSSession) D4Fingerprinting(fd string) bool {
	switch fd {
	case "ja3":
		t.ja3()
	case "ja3s":
		t.ja3s()
	case "tlsh":
		t.d4fg()
	default:
		return false
	}

	return true
}

func (t *TLSSession) d4fg() string {
	buf := t.Record.JA3 + t.Record.JA3S
	for _, cert := range t.Record.Certificates {
		buf += fmt.Sprintf("%q", cert.Issuer) + fmt.Sprintf("%q", cert.Subject)
	}
	buf = strings.Replace(buf, "-", "", -1)
	buf = strings.Replace(buf, ",", "", -1)
	buf = strings.Replace(buf, "\"", "", -1)

	out, _ := tlsh.HashBytes([]byte(buf))
	t.Record.TLSH = out.String()
	return buf
}

func (t *TLSSession) ja3s() bool {
	var buf []byte
	buf = strconv.AppendInt(buf, int64(t.handShakeRecord.ETLSHandshakeServerHello.Vers), 10)
	// byte (44) is ","
	buf = append(buf, byte(44))

	// If the Server Cipher is not in GREASE
	if grease[uint16(t.handShakeRecord.ETLSHandshakeServerHello.CipherSuite)] == false {
		buf = strconv.AppendInt(buf, int64(t.handShakeRecord.ETLSHandshakeServerHello.CipherSuite), 10)
	}
	buf = append(buf, byte(44))

	// If there are extensions
	if len(t.handShakeRecord.ETLSHandshakeServerHello.AllExtensions) > 0 {
		for i, e := range t.handShakeRecord.ETLSHandshakeServerHello.AllExtensions {
			if grease[uint16(e)] == false {
				buf = strconv.AppendInt(buf, int64(e), 10)
				if (i + 1) < len(t.handShakeRecord.ETLSHandshakeServerHello.AllExtensions) {
					// byte(45) is "-"
					buf = append(buf, byte(45))
				}
			}
		}
	}

	t.Record.JA3S = string(buf)
	tmp := md5.Sum(buf)
	t.Record.JA3SDigest = hex.EncodeToString(tmp[:])

	return true
}

func (t *TLSSession) ja3() bool {
	var buf []byte
	buf = strconv.AppendInt(buf, int64(t.handShakeRecord.ETLSHandshakeClientHello.Vers), 10)
	// byte (44) is ","
	buf = append(buf, byte(44))

	// If there are Cipher Suites
	if len(t.handShakeRecord.ETLSHandshakeClientHello.CipherSuites) > 0 {
		for i, cs := range t.handShakeRecord.ETLSHandshakeClientHello.CipherSuites {
			if grease[uint16(cs)] == false {
				buf = strconv.AppendInt(buf, int64(cs), 10)
				// byte(45) is "-"
				if (i + 1) < len(t.handShakeRecord.ETLSHandshakeClientHello.CipherSuites) {
					buf = append(buf, byte(45))
				}
			}
		}
	}
	buf = append(buf, byte(44))

	// If there are extensions
	if len(t.handShakeRecord.ETLSHandshakeClientHello.AllExtensions) > 0 {
		for i, e := range t.handShakeRecord.ETLSHandshakeClientHello.AllExtensions {
			if grease[uint16(e)] == false {
				buf = strconv.AppendInt(buf, int64(e), 10)
				if (i + 1) < len(t.handShakeRecord.ETLSHandshakeClientHello.AllExtensions) {
					buf = append(buf, byte(45))
				}
			}
		}
	}
	buf = append(buf, byte(44))

	// If there are Supported Curves
	if len(t.handShakeRecord.ETLSHandshakeClientHello.SupportedCurves) > 0 {
		for i, cs := range t.handShakeRecord.ETLSHandshakeClientHello.SupportedCurves {
			buf = strconv.AppendInt(buf, int64(cs), 10)
			if (i + 1) < len(t.handShakeRecord.ETLSHandshakeClientHello.SupportedCurves) {
				buf = append(buf, byte(45))
			}
		}
	}
	buf = append(buf, byte(44))

	// If there are Supported Points
	if len(t.handShakeRecord.ETLSHandshakeClientHello.SupportedPoints) > 0 {
		for i, cs := range t.handShakeRecord.ETLSHandshakeClientHello.SupportedPoints {
			buf = strconv.AppendInt(buf, int64(cs), 10)
			if (i + 1) < len(t.handShakeRecord.ETLSHandshakeClientHello.SupportedPoints) {
				buf = append(buf, byte(45))
			}
		}
	}
	t.Record.JA3 = string(buf)
	tmp := md5.Sum(buf)
	t.Record.JA3Digest = hex.EncodeToString(tmp[:])
	return true
}
