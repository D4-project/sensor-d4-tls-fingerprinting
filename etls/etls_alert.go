// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package etls

import (
	"errors"
	"fmt"

	"github.com/google/gopacket"
)

// ETLSAlertLevel defines the alert level data type
type ETLSAlertLevel uint8

// ETLSAlertDescr defines the alert descrption data type
type ETLSAlertDescr uint8

const (
	ETLSAlertWarning      ETLSAlertLevel = 1
	ETLSAlertFatal        ETLSAlertLevel = 2
	ETLSAlertUnknownLevel ETLSAlertLevel = 255

	ETLSAlertCloseNotify               ETLSAlertDescr = 0
	ETLSAlertUnexpectedMessage         ETLSAlertDescr = 10
	ETLSAlertBadRecordMac              ETLSAlertDescr = 20
	ETLSAlertDecryptionFailedRESERVED  ETLSAlertDescr = 21
	ETLSAlertRecordOverflow            ETLSAlertDescr = 22
	ETLSAlertDecompressionFailure      ETLSAlertDescr = 30
	ETLSAlertHandshakeFailure          ETLSAlertDescr = 40
	ETLSAlertNoCertificateRESERVED     ETLSAlertDescr = 41
	ETLSAlertBadCertificate            ETLSAlertDescr = 42
	ETLSAlertUnsupportedCertificate    ETLSAlertDescr = 43
	ETLSAlertCertificateRevoked        ETLSAlertDescr = 44
	ETLSAlertCertificateExpired        ETLSAlertDescr = 45
	ETLSAlertCertificateUnknown        ETLSAlertDescr = 46
	ETLSAlertIllegalParameter          ETLSAlertDescr = 47
	ETLSAlertUnknownCa                 ETLSAlertDescr = 48
	ETLSAlertAccessDenied              ETLSAlertDescr = 49
	ETLSAlertDecodeError               ETLSAlertDescr = 50
	ETLSAlertDecryptError              ETLSAlertDescr = 51
	ETLSAlertExportRestrictionRESERVED ETLSAlertDescr = 60
	ETLSAlertProtocolVersion           ETLSAlertDescr = 70
	ETLSAlertInsufficientSecurity      ETLSAlertDescr = 71
	ETLSAlertInternalError             ETLSAlertDescr = 80
	ETLSAlertUserCanceled              ETLSAlertDescr = 90
	ETLSAlertNoRenegotiation           ETLSAlertDescr = 100
	ETLSAlertUnsupportedExtension      ETLSAlertDescr = 110
	ETLSAlertUnknownDescription        ETLSAlertDescr = 255
)

//  ETLS Alert
//  0  1  2  3  4  5  6  7  8
//  +--+--+--+--+--+--+--+--+
//  |         Level         |
//  +--+--+--+--+--+--+--+--+
//  |      Description      |
//  +--+--+--+--+--+--+--+--+

// ETLSAlertRecord contains all the information that each Alert Record type should have
type ETLSAlertRecord struct {
	ETLSRecordHeader

	Level       ETLSAlertLevel
	Description ETLSAlertDescr

	EncryptedMsg []byte
}

// DecodeFromBytes decodes the slice into the ETLS struct.
func (t *ETLSAlertRecord) decodeFromBytes(h ETLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// ETLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if len(data) < 2 {
		df.SetTruncated()
		return errors.New("ETLS Alert packet too short")
	}

	if t.Length == 2 {
		t.Level = ETLSAlertLevel(data[0])
		t.Description = ETLSAlertDescr(data[1])
	} else {
		t.Level = ETLSAlertUnknownLevel
		t.Description = ETLSAlertUnknownDescription
		t.EncryptedMsg = data
	}

	return nil
}

// Strings shows the ETLS alert level nicely formatted
func (al ETLSAlertLevel) String() string {
	switch al {
	default:
		return fmt.Sprintf("Unknown(%d)", al)
	case ETLSAlertWarning:
		return "Warning"
	case ETLSAlertFatal:
		return "Fatal"
	}
}

// Strings shows the ETLS alert description nicely formatted
func (ad ETLSAlertDescr) String() string {
	switch ad {
	default:
		return "Unknown"
	case ETLSAlertCloseNotify:
		return "close_notify"
	case ETLSAlertUnexpectedMessage:
		return "unexpected_message"
	case ETLSAlertBadRecordMac:
		return "bad_record_mac"
	case ETLSAlertDecryptionFailedRESERVED:
		return "decryption_failed_RESERVED"
	case ETLSAlertRecordOverflow:
		return "record_overflow"
	case ETLSAlertDecompressionFailure:
		return "decompression_failure"
	case ETLSAlertHandshakeFailure:
		return "handshake_failure"
	case ETLSAlertNoCertificateRESERVED:
		return "no_certificate_RESERVED"
	case ETLSAlertBadCertificate:
		return "bad_certificate"
	case ETLSAlertUnsupportedCertificate:
		return "unsupported_certificate"
	case ETLSAlertCertificateRevoked:
		return "certificate_revoked"
	case ETLSAlertCertificateExpired:
		return "certificate_expired"
	case ETLSAlertCertificateUnknown:
		return "certificate_unknown"
	case ETLSAlertIllegalParameter:
		return "illegal_parameter"
	case ETLSAlertUnknownCa:
		return "unknown_ca"
	case ETLSAlertAccessDenied:
		return "access_denied"
	case ETLSAlertDecodeError:
		return "decode_error"
	case ETLSAlertDecryptError:
		return "decrypt_error"
	case ETLSAlertExportRestrictionRESERVED:
		return "export_restriction_RESERVED"
	case ETLSAlertProtocolVersion:
		return "protocol_version"
	case ETLSAlertInsufficientSecurity:
		return "insufficient_security"
	case ETLSAlertInternalError:
		return "internal_error"
	case ETLSAlertUserCanceled:
		return "user_canceled"
	case ETLSAlertNoRenegotiation:
		return "no_renegotiation"
	case ETLSAlertUnsupportedExtension:
		return "unsupported_extension"
	}
}
