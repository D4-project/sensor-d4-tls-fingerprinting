package d4tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/D4-project/sensor-d4-tls-fingerprinting/etls"
)

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
	state           HandshakeState
}

// HandshakeComplete returns true if the TLS session has seen all three client helo, server helo and the certificate.
func (t *TLSSession) HandshakeComplete() bool {
	return t.state.Has(StateClientHello) &&
		t.state.Has(StateServerHello) &&
		t.state.Has(StateCertificate)
}

// HandshakePartially returns true if the client hello and server hello is set, but not the certificate.
func (t *TLSSession) HandshakePartially() bool {
	return t.state.Has(StateClientHello) &&
		t.state.Has(StateServerHello) &&
		!t.state.Has(StateCertificate)
}

// HandshakeAny returns true if any of the client or server has been seen
func (t *TLSSession) HandshakeAny() bool {
	return t.state.Has(StateClientHello) ||
		t.state.Has(StateServerHello)
}

func (t *TLSSession) HandshakeState() string {
	return fmt.Sprintf("ClientHello:%t ServerHello:%t Certificate:%t",
		t.state.Has(StateClientHello),
		t.state.Has(StateServerHello),
		t.state.Has(StateCertificate),
	)
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

// SetNetwork sets the network part in the TLSSession.Record struct.
func (t *TLSSession) SetNetwork(cip string, sip string, cp string, sp string) {
	t.Record.ClientIP = cip
	t.Record.ServerIP = sip
	t.Record.ClientPort = cp
	t.Record.ServerPort = sp
}

// SetTimestamp sets the timestamp of this TLSSession in its TLSSession.Record struct
func (t *TLSSession) SetTimestamp(ti time.Time) {
	t.Record.Timestamp = ti
}

// PopulateClientHello takes a pointer to an etls ClientHelloMsg and writes it to the the TLSSession struct
func (t *TLSSession) PopulateClientHello(h *etls.ClientHelloMsg) {
	t.state.Set(StateClientHello)
	t.handShakeRecord.ETLSHandshakeClientHello = h
}

// PopulateServerHello takes a pointer to an etls ServerHelloMsg and writes it to the TLSSession struct
func (t *TLSSession) PopulateServerHello(h *etls.ServerHelloMsg) {
	t.state.Set(StateServerHello)
	t.handShakeRecord.ETLSHandshakeServerHello = h
}

// PopulateCertificate takes a pointer to an etls ServerHelloMsg and writes it to the TLSSession struct
func (t *TLSSession) PopulateCertificate(c *etls.CertificateMsg) {
	t.state.Set(StateCertificate)
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
