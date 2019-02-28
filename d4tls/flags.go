package d4tls

// HandshakeState is a flag which keeps record of which handeshake message types
// have been parsed.
type HandshakeState uint8

const (
	StateClientHello = 1 << iota
	StateServerHello
	StateCertificate
)

func (s *HandshakeState) Set(flag HandshakeState) {
	*s |= flag
}

func (s HandshakeState) Has(flag HandshakeState) bool {
	return s&flag != 0
}
