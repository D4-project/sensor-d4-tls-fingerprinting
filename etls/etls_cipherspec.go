// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package etls

import (
	"errors"

	"github.com/google/gopacket"
)

// ETLSchangeCipherSpec defines the message value inside ChangeCipherSpec Record
type ETLSchangeCipherSpec uint8

const (
	ETLSChangecipherspecMessage ETLSchangeCipherSpec = 1
	ETLSChangecipherspecUnknown ETLSchangeCipherSpec = 255
)

//  ETLS Change Cipher Spec
//  0  1  2  3  4  5  6  7  8
//  +--+--+--+--+--+--+--+--+
//  |        Message        |
//  +--+--+--+--+--+--+--+--+

// ETLSChangeCipherSpecRecord defines the type of data inside ChangeCipherSpec Record
type ETLSChangeCipherSpecRecord struct {
	ETLSRecordHeader

	Message ETLSchangeCipherSpec
}

// DecodeFromBytes decodes the slice into the ETLS struct.
func (t *ETLSChangeCipherSpecRecord) decodeFromBytes(h ETLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// ETLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if len(data) != 1 {
		df.SetTruncated()
		return errors.New("ETLS Change Cipher Spec record incorrect length")
	}

	t.Message = ETLSchangeCipherSpec(data[0])
	if t.Message != ETLSChangecipherspecMessage {
		t.Message = ETLSChangecipherspecUnknown
	}

	return nil
}

// String shows the message value nicely formatted
func (ccs ETLSchangeCipherSpec) String() string {
	switch ccs {
	default:
		return "Unknown"
	case ETLSChangecipherspecMessage:
		return "Change Cipher Spec Message"
	}
}
