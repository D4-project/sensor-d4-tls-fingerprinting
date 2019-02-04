// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package etls

import (
	"github.com/google/gopacket"
)

// ETLSHandshakeRecord defines the structure of a Handskake Record
type ETLSHandshakeRecord struct {
	ETLSRecordHeader
	ETLSHandshakeMsgType     uint8
	ETLSHandshakeServerHello *ServerHelloMsg
	ETLSHandshakeClientHello *ClientHelloMsg
	ETLSHandshakeCertificate *CertificateMsg
}

// DecodeFromBytes decodes the slice into the ETLS struct.
func (t *ETLSHandshakeRecord) decodeFromBytes(h ETLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// ETLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	// Switch on Handshake message type
	switch uint8(data[0]) {
	case typeClientHello:
		t.ETLSHandshakeMsgType = typeClientHello
		t.ETLSHandshakeClientHello = new(ClientHelloMsg)
		t.ETLSHandshakeClientHello.unmarshal(data)
	case typeServerHello:
		t.ETLSHandshakeMsgType = typeServerHello
		t.ETLSHandshakeServerHello = new(ServerHelloMsg)
		t.ETLSHandshakeServerHello.unmarshal(data)
	case typeCertificate:
		t.ETLSHandshakeMsgType = typeCertificate
		t.ETLSHandshakeCertificate = new(CertificateMsg)
		t.ETLSHandshakeCertificate.unmarshal(data)
	}
	// Please see the following url if you are interested into implementing the rest:
	// https://golang.org/src/crypto/tls/conn.go?h=readHandshake#L950

	return nil
}
