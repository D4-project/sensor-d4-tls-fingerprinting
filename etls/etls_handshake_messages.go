// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Most of this content was extracted from go tls package

package etls

type handshakeMessage interface {
	unmarshal([]byte) bool
}

type clientHelloMsg struct {
	raw                          []byte
	extensions                   map[Extension]uint16
	AllExtensions                []uint16
	Vers                         uint16
	random                       []byte
	sessionId                    []byte
	CipherSuites                 []uint16
	compressionMethods           []uint8
	nextProtoNeg                 bool
	serverName                   string
	ocspStapling                 bool
	scts                         bool
	SupportedCurves              []CurveID
	SupportedPoints              []uint8
	ticketSupported              bool
	sessionTicket                []uint8
	supportedSignatureAlgorithms []SignatureScheme
	secureRenegotiation          []byte
	secureRenegotiationSupported bool
	alpnProtocols                []string
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}

	m.raw = data
	m.Vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}

	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 2 {
		return false
	}

	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}

	numCipherSuites := cipherSuiteLen / 2
	m.CipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.CipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
		if m.CipherSuites[i] == scsvRenegotiation {
			m.secureRenegotiationSupported = true
		}
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}

	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false
	}

	m.compressionMethods = data[1 : 1+compressionMethodsLen]
	data = data[1+compressionMethodsLen:]
	m.nextProtoNeg = false
	m.serverName = ""
	m.ocspStapling = false
	m.ticketSupported = false
	m.sessionTicket = nil
	m.supportedSignatureAlgorithms = nil
	m.alpnProtocols = nil
	m.scts = false

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return true
	}

	if len(data) < 2 {
		return false

	}

	// We parse extensions as their needed for ja3
	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	m.extensions = make(map[Extension]uint16)

	if extensionsLength != len(data) {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]

		m.AllExtensions = append(m.AllExtensions, uint16(extension))

		if len(data) < length {
			return false
		}

		switch extension {
		case extensionSupportedCurves:
			// https://tools.ietf.org/html/rfc4492#section-5.5.1
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l%2 == 1 || length != l+2 {
				return false
			}
			numCurves := l / 2
			m.SupportedCurves = make([]CurveID, numCurves)
			d := data[2:]
			for i := 0; i < numCurves; i++ {
				m.SupportedCurves[i] = CurveID(d[0])<<8 | CurveID(d[1])
				d = d[2:]
			}
		case extensionSupportedPoints:
			// https://tools.ietf.org/html/rfc4492#section-5.5.2
			if length < 1 {
				return false
			}
			l := int(data[0])
			if length != l+1 {
				return false
			}
			m.SupportedPoints = make([]uint8, l)
			copy(m.SupportedPoints, data[1:])
		}

		data = data[length:]
	}
	return true
}

type serverHelloMsg struct {
	raw                          []byte
	extensions                   map[Extension]uint16
	AllExtensions                []uint16
	Vers                         uint16
	random                       []byte
	sessionId                    []byte
	CipherSuite                  uint16
	compressionMethod            uint8
	nextProtoNeg                 bool
	nextProtos                   []string
	ocspStapling                 bool
	scts                         [][]byte
	ticketSupported              bool
	secureRenegotiation          []byte
	secureRenegotiationSupported bool
	alpnProtocol                 string
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}

	m.raw = data
	m.Vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 3 {
		return false
	}
	m.CipherSuite = uint16(data[0])<<8 | uint16(data[1])
	m.compressionMethod = data[2]
	data = data[3:]

	m.nextProtoNeg = false
	m.nextProtos = nil
	m.ocspStapling = false
	m.scts = nil
	m.ticketSupported = false
	m.alpnProtocol = ""
	if len(data) == 0 {
		// ServerHello is optionally followed by extension data
		return true
	}

	if len(data) < 2 {
		return false
	}

	// Import Extension code needed for ja3s
	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	m.extensions = make(map[Extension]uint16)

	if len(data) != extensionsLength {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]

		m.AllExtensions = append(m.AllExtensions, uint16(extension))

		if len(data) < length {
			return false
		}

		switch extension {

		case extensionNextProtoNeg:
			m.nextProtoNeg = true
			d := data[:length]
			for len(d) > 0 {
				l := int(d[0])
				d = d[1:]
				if l == 0 || l > len(d) {
					return false
				}
				m.nextProtos = append(m.nextProtos, string(d[:l]))
				d = d[l:]
			}

		case extensionStatusRequest:
			if length > 0 {
				return false
			}
			m.ocspStapling = true

		case extensionSessionTicket:
			if length > 0 {
				return false
			}
			m.ticketSupported = true

		case extensionRenegotiationInfo:
			if length == 0 {
				return false
			}
			d := data[:length]
			l := int(d[0])
			d = d[1:]
			if l != len(d) {
				return false
			}

			m.secureRenegotiation = d
			m.secureRenegotiationSupported = true

		case extensionALPN:
			d := data[:length]
			if len(d) < 3 {
				return false
			}
			l := int(d[0])<<8 | int(d[1])
			if l != len(d)-2 {
				return false
			}
			d = d[2:]
			l = int(d[0])
			if l != len(d)-1 {
				return false
			}
			d = d[1:]
			if len(d) == 0 {
				// ALPN protocols must not be empty.
				return false
			}
			m.alpnProtocol = string(d)

		case extensionSCT:
			d := data[:length]
			if len(d) < 2 {
				return false
			}
			l := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != l || l == 0 {
				return false
			}
			m.scts = make([][]byte, 0, 3)
			for len(d) != 0 {
				if len(d) < 2 {
					return false
				}
				sctLen := int(d[0])<<8 | int(d[1])
				d = d[2:]
				if sctLen == 0 || len(d) < sctLen {
					return false
				}
				m.scts = append(m.scts, d[:sctLen])
				d = d[sctLen:]
			}
		}
		data = data[length:]
	}
	return true
}

type certificateMsg struct {
	raw          []byte
	Certificates [][]byte
}

func (m *certificateMsg) unmarshal(data []byte) bool {
	if len(data) < 7 {
		return false
	}
	m.raw = data
	certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
	if uint32(len(data)) != certsLen+7 {
		return false
	}
	numCerts := 0
	d := data[7:]
	for certsLen > 0 {
		if len(d) < 4 {
			return false
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return false
		}
		d = d[3+certLen:]
		certsLen -= 3 + certLen
		numCerts++
	}

	m.Certificates = make([][]byte, numCerts)
	d = data[7:]

	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.Certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return true
}
