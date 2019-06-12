package d4tls

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/glaslos/tlsh"
)

// see https://tools.ietf.org/html/draft-ietf-tls-grease-02
// grease values for cipher suites, ALPN and identifiers,
// extensions, named groups, signatur algorithms, and versions.
var grease = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// D4Fingerprinting computes fingerprints
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
			if grease[uint16(cs)] == false {
				buf = strconv.AppendInt(buf, int64(cs), 10)
				if (i + 1) < len(t.handShakeRecord.ETLSHandshakeClientHello.SupportedCurves) {
					buf = append(buf, byte(45))
				}
			}
		}
	}
	buf = append(buf, byte(44))

	// If there are Supported Points
	if len(t.handShakeRecord.ETLSHandshakeClientHello.SupportedPoints) > 0 {
		for i, cs := range t.handShakeRecord.ETLSHandshakeClientHello.SupportedPoints {
			if grease[uint16(cs)] == false {
				buf = strconv.AppendInt(buf, int64(cs), 10)
				if (i + 1) < len(t.handShakeRecord.ETLSHandshakeClientHello.SupportedPoints) {
					buf = append(buf, byte(45))
				}
			}
		}
	}
	t.Record.JA3 = string(buf)
	tmp := md5.Sum(buf)
	t.Record.JA3Digest = hex.EncodeToString(tmp[:])
	return true
}
