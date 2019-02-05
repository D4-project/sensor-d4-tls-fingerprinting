// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package etls

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypeETLS gopacket.LayerType

// ETLSType defines the type of data after the ETLS Record
type ETLSType uint8

// ETLSType known values.
const (
	ETLSChangeCipherSpec ETLSType = 20
	ETLSAlert            ETLSType = 21
	ETLSHandshake        ETLSType = 22
	ETLSApplicationData  ETLSType = 23
	ETLSUnknown          ETLSType = 255
)

// String shows the register type nicely formatted
func (tt ETLSType) String() string {
	switch tt {
	default:
		return "Unknown"
	case ETLSChangeCipherSpec:
		return "Change Cipher Spec"
	case ETLSAlert:
		return "Alert"
	case ETLSHandshake:
		return "Handshake"
	case ETLSApplicationData:
		return "Application Data"
	}
}

// ETLSVersion represents the ETLS version in numeric format
type ETLSVersion uint16

// Strings shows the ETLS version nicely formatted
func (tv ETLSVersion) String() string {
	switch tv {
	default:
		return "Unknown"
	case 0x0200:
		return "SSL 2.0"
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
}

// ETLS is specified in RFC 5246
//
//  ETLS Record Protocol
//  0  1  2  3  4  5  6  7  8
//  +--+--+--+--+--+--+--+--+
//  |     Content Type      |
//  +--+--+--+--+--+--+--+--+
//  |    Version (major)    |
//  +--+--+--+--+--+--+--+--+
//  |    Version (minor)    |
//  +--+--+--+--+--+--+--+--+
//  |        Length         |
//  +--+--+--+--+--+--+--+--+
//  |        Length         |
//  +--+--+--+--+--+--+--+--+

// ETLS is actually a slide of ETLSrecord structures
type ETLS struct {
	layers.BaseLayer

	// ETLS Records
	ChangeCipherSpec []ETLSChangeCipherSpecRecord
	Handshake        []ETLSHandshakeRecord
	AppData          []ETLSAppDataRecord
	Alert            []ETLSAlertRecord
}

// ETLSRecordHeader contains all the information that each ETLS Record types should have
type ETLSRecordHeader struct {
	ContentType ETLSType
	Version     ETLSVersion
	Length      uint16
}

// LayerType returns gopacket.LayerTypeETLS.
func (t *ETLS) LayerType() gopacket.LayerType { return LayerTypeETLS }

// decodeETLS decodes the byte slice into a ETLS type. It also
// setups the application Layer in PacketBuilder.
func decodeETLS(data []byte, p gopacket.PacketBuilder) error {
	t := &ETLS{}
	err := t.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(t)
	p.SetApplicationLayer(t)
	return nil
}

// DecodeFromBytes decodes the slice into the ETLS struct.
func (t *ETLS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	t.BaseLayer.Contents = data
	t.BaseLayer.Payload = nil

	t.ChangeCipherSpec = t.ChangeCipherSpec[:0]
	t.Handshake = t.Handshake[:0]
	t.AppData = t.AppData[:0]
	t.Alert = t.Alert[:0]

	return t.decodeETLSRecords(data, df)
}

func (t *ETLS) decodeETLSRecords(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 5 {
		df.SetTruncated()
		return errors.New("ETLS record too short")
	}

	// since there are no further layers, the baselayer's content is
	// pointing to this layer
	t.BaseLayer = layers.BaseLayer{Contents: data[:len(data)]}

	var h ETLSRecordHeader
	h.ContentType = ETLSType(data[0])
	h.Version = ETLSVersion(binary.BigEndian.Uint16(data[1:3]))
	h.Length = binary.BigEndian.Uint16(data[3:5])

	if h.ContentType.String() == "Unknown" {
		return errors.New("Unknown ETLS record type")
	}

	hl := 5 // header length
	tl := hl + int(h.Length)
	if len(data) < tl {
		df.SetTruncated()
		return errors.New("ETLS packet length mismatch")
	}

	switch h.ContentType {
	default:
		return errors.New("Unknown ETLS record type")
	case ETLSChangeCipherSpec:
		var r ETLSChangeCipherSpecRecord
		e := r.decodeFromBytes(h, data[hl:tl], df)
		if e != nil {
			return e
		}
		t.ChangeCipherSpec = append(t.ChangeCipherSpec, r)
	case ETLSAlert:
		var r ETLSAlertRecord
		e := r.decodeFromBytes(h, data[hl:tl], df)
		if e != nil {
			return e
		}
		t.Alert = append(t.Alert, r)
	case ETLSHandshake:
		var r ETLSHandshakeRecord
		e := r.decodeFromBytes(h, data[hl:tl], df)
		if e != nil {
			return e
		}
		t.Handshake = append(t.Handshake, r)
	case ETLSApplicationData:
		var r ETLSAppDataRecord
		e := r.decodeFromBytes(h, data[hl:tl], df)
		if e != nil {
			return e
		}
		t.AppData = append(t.AppData, r)
	}

	if len(data) == tl {
		return nil
	}
	return t.decodeETLSRecords(data[tl:len(data)], df)
}

// CanDecode implements gopacket.DecodingLayer.
func (t *ETLS) CanDecode() gopacket.LayerClass {
	return LayerTypeETLS
}

// NextLayerType implements gopacket.DecodingLayer.
func (t *ETLS) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// Payload returns nil, since ETLS encrypted payload is inside ETLSAppDataRecord
func (t *ETLS) Payload() []byte {
	return nil
}

func init() {
	LayerTypeETLS = gopacket.RegisterLayerType(1337, gopacket.LayerTypeMetadata{Name: "ETLS", Decoder: gopacket.DecodeFunc(decodeETLS)})
}
