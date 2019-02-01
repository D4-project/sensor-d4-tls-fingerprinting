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

// ETLSAppDataRecord contains all the information that each AppData Record types should have
type ETLSAppDataRecord struct {
	ETLSRecordHeader
	Payload []byte
}

// DecodeFromBytes decodes the slice into the ETLS struct.
func (t *ETLSAppDataRecord) decodeFromBytes(h ETLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// ETLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if len(data) != int(t.Length) {
		return errors.New("ETLS Application Data length mismatch")
	}

	t.Payload = data
	return nil
}
