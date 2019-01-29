// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
package main

import (
	"bytes"
	"crypto/md5"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/ip4defrag"

	// ATM add a fork to gopacket like this to pull my TLS code:
	// $go get github.com/gallypette/gopacket
	// $cd $GOPATH/src/github.com/google/gopacket
	// $git remote add fork github.com/gallypette/gopacket
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)

var maxcount = flag.Int("c", -1, "Only grab this many packets, then exit")
var decoder = flag.String("decoder", "", "Name of the decoder to use (default: guess from capture)")
var statsevery = flag.Int("stats", 1000, "Output statistics every N packets")
var lazy = flag.Bool("lazy", false, "If true, do lazy decoding")
var nodefrag = flag.Bool("nodefrag", false, "If true, do not do IPv4 defrag")
var checksum = flag.Bool("checksum", false, "Check TCP checksum")
var nooptcheck = flag.Bool("nooptcheck", false, "Do not check TCP options (useful to ignore MSS on captures with TSO)")
var ignorefsmerr = flag.Bool("ignorefsmerr", false, "Ignore TCP FSM errors")
var allowmissinginit = flag.Bool("allowmissinginit", false, "Support streams without SYN/SYN+ACK/ACK sequence")
var verbose = flag.Bool("verbose", false, "Be verbose")
var debug = flag.Bool("debug", false, "Display debug information")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")

// capture
var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")

// writing
var outCerts = flag.String("w", "", "Folder to write certificates into")
var outJSON = flag.String("j", "", "Folder to write certificates into, stdin if not set")
var jobQ chan TLSSession
var cancelC chan string

var memprofile = flag.String("memprofile", "", "Write memory profile")

var stats struct {
	ipdefrag            int
	missedBytes         int
	pkt                 int
	sz                  int
	totalsz             int
	rejectFsm           int
	rejectOpt           int
	rejectConnFsm       int
	reassembled         int
	outOfOrderBytes     int
	outOfOrderPackets   int
	biggestChunkBytes   int
	biggestChunkPackets int
	overlapBytes        int
	overlapPackets      int
}

type SessionRecord struct {
	ServerIP     string
	ServerPort   string
	ClientIP     string
	ClientPort   string
	TLSHDigest   string
	Timestamp    time.Time
	JA3          string
	JA3Digest    string
	JA3S         string
	JA3SDigest   string
	Certificates []*x509.Certificate
}

type TLSSession struct {
	record   SessionRecord
	tlsHdskR layers.TLSHandshakeRecord
}

var grease = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

const closeTimeout time.Duration = time.Hour * 24 // Closing inactive: TODO: from CLI
const timeout time.Duration = time.Minute * 5     // Pending bytes: TODO: from CLI

var outputLevel int
var errorsMap map[string]uint
var errorsMapMutex sync.Mutex
var errors uint

func (t *TLSSession) String() string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("---------------SESSION START-------------------\n"))
	buf.WriteString(fmt.Sprintf("Time: %d\n", t.record.Timestamp))
	buf.WriteString(fmt.Sprintf("Client: %v:%v\n", t.record.ClientIP, t.record.ClientPort))
	buf.WriteString(fmt.Sprintf("Server: %v:%v\n", t.record.ServerIP, t.record.ServerPort))
	buf.WriteString(fmt.Sprintf("ja3: %q\n", t.record.JA3))
	buf.WriteString(fmt.Sprintf("ja3 Digest: %q\n", t.record.JA3Digest))
	buf.WriteString(fmt.Sprintf("ja3s: %q\n", t.record.JA3S))
	buf.WriteString(fmt.Sprintf("ja3s Digest: %q\n", t.record.JA3SDigest))
	for _, cert := range t.record.Certificates {
		buf.WriteString(fmt.Sprintf("Certificate Issuer: %q\n", cert.Issuer))
		buf.WriteString(fmt.Sprintf("Certificate Subject: %q\n", cert.Subject))
		buf.WriteString(fmt.Sprintf("Certificate is CA: %t\n", cert.IsCA))
	}
	buf.WriteString(fmt.Sprintf("---------------SESSION  END--------------------\n"))
	return buf.String()
}

// Too bad for perf that a... is evaluated
func Error(t string, s string, a ...interface{}) {
	errorsMapMutex.Lock()
	errors++
	nb, _ := errorsMap[t]
	errorsMap[t] = nb + 1
	errorsMapMutex.Unlock()
	if outputLevel >= 0 {
		//fmt.Printf(s, a...)
	}
}
func Info(s string, a ...interface{}) {
	if outputLevel >= 1 {
		fmt.Printf(s, a...)
	}
}
func Debug(s string, a ...interface{}) {
	if outputLevel >= 2 {
		fmt.Printf(s, a...)
	}
}

/*
 * The TCP factory: returns a new Stream
 */
type tcpStreamFactory struct {
	wg sync.WaitGroup
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	Debug("* NEW: %s %s\n", net, transport)
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: *allowmissinginit,
	}
	stream := &tcpStream{
		net:        net,
		transport:  transport,
		isTLS:      true,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		optchecker: reassembly.NewTCPOptionCheck(),
	}
	return stream
}

func (factory *tcpStreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}

/*
 * The assembler context
 */
type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

/*
 * TCP stream
 */

/* It's a connection (bidirectional) */
type tcpStream struct {
	tcpstate       *reassembly.TCPSimpleFSM
	fsmerr         bool
	optchecker     reassembly.TCPOptionCheck
	net, transport gopacket.Flow
	isTLS          bool
	reversed       bool
	urls           []string
	ident          string
	tlsSession     TLSSession
	sync.Mutex
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		Error("FSM", "%s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
		stats.rejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			stats.rejectConnFsm++
		}
		if !*ignorefsmerr {
			return false
		}
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		Error("OptionChecker", "%s: Packet rejected by OptionChecker: %s\n", t.ident, err)
		stats.rejectOpt++
		if !*nooptcheck {
			return false
		}
	}
	// Checksum
	accept := true
	if *checksum {
		c, err := tcp.ComputeChecksum()
		if err != nil {
			Error("ChecksumCompute", "%s: Got error computing checksum: %s\n", t.ident, err)
			accept = false
		} else if c != 0x0 {
			Error("Checksum", "%s: Invalid checksum: 0x%x\n", t.ident, c)
			accept = false
		}
	}
	if !accept {
		stats.rejectOpt++
	}
	return accept
}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, start, end, skip := sg.Info()
	length, saved := sg.Lengths()
	// update stats
	sgStats := sg.Stats()
	if skip > 0 {
		stats.missedBytes += skip
	}
	stats.sz += length - saved
	stats.pkt += sgStats.Packets
	if sgStats.Chunks > 1 {
		stats.reassembled++
	}
	stats.outOfOrderPackets += sgStats.QueuedPackets
	stats.outOfOrderBytes += sgStats.QueuedBytes
	if length > stats.biggestChunkBytes {
		stats.biggestChunkBytes = length
	}
	if sgStats.Packets > stats.biggestChunkPackets {
		stats.biggestChunkPackets = sgStats.Packets
	}
	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		fmt.Printf("bytes:%d, pkts:%d\n", sgStats.OverlapBytes, sgStats.OverlapPackets)
		panic("Invalid overlap")
	}
	stats.overlapBytes += sgStats.OverlapBytes
	stats.overlapPackets += sgStats.OverlapPackets

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}
	Debug("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)
	if skip == -1 && *allowmissinginit {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}
	data := sg.Fetch(length)
	if t.isTLS {
		if length > 0 {
			// We can't rely on TLS length field has there can be several successive Record Layers
			// We attempt to decode, and if it fails, we keep the slice for later.
			// Now we attempts TLS decoding
			tls := &layers.TLS{}
			var decoded []gopacket.LayerType
			// First we check if the packet is fragmented
			p := gopacket.NewDecodingLayerParser(layers.LayerTypeTLS, tls)
			err := p.DecodeLayers(data, &decoded)
			if err != nil {
				//			Error("TLS-parser", "Failed to decode TLS: %v\n", err)
				//				Debug("RAW %s\n", hex.Dump(data))
				sg.KeepFrom(0)
			} else {
				//Debug("TLS: %s\n", gopacket.LayerDump(tls))
				//		Debug("TLS: %s\n", gopacket.LayerGoString(tls))
				if tls.Handshake != nil {
					for _, tlsrecord := range tls.Handshake {
						switch tlsrecord.TLSHandshakeMsgType {
						// Client Hello
						case 1:
							t.tlsSession.tlsHdskR.TLSHandshakeClientHello = tlsrecord.TLSHandshakeClientHello
							t.tlsSession.record.ClientIP, t.tlsSession.record.ServerIP, t.tlsSession.record.ClientPort, t.tlsSession.record.ServerPort = getIPPorts(t)
							// Set up first seen
							info := sg.CaptureInfo(0)
							t.tlsSession.record.Timestamp = info.Timestamp
							t.tlsSession.gatherJa3()
						// Server Hello
						case 2:
							t.tlsSession.tlsHdskR.TLSHandshakeServerHello = tlsrecord.TLSHandshakeServerHello
							t.tlsSession.gatherJa3s()
						// Server Certificate
						case 11:
							//certs := make([]*x509.Certificate, len(tlsrecord.TLSHandshakeCertificate.Certificates))
							for _, asn1Data := range tlsrecord.TLSHandshakeCertificate.Certificates {
								cert, err := x509.ParseCertificate(asn1Data)
								if err != nil {
									panic("tls: failed to parse certificate from server: " + err.Error())
								} else {
									t.tlsSession.record.Certificates = append(t.tlsSession.record.Certificates, cert)
								}
							}
							// If we get a cert, we consider the handshake as finished and ready to ship to D4
							queueSession(t.tlsSession)
						default:
							break
						}
					}
				}
			}
		}
	}
}

func getIPPorts(t *tcpStream) (string, string, string, string) {
	tmp := strings.Split(fmt.Sprintf("%v", t.net), "->")
	ipc := tmp[0]
	ips := tmp[1]
	tmp = strings.Split(fmt.Sprintf("%v", t.transport), "->")
	cp := tmp[0]
	ps := tmp[1]
	return ipc, ips, cp, ps
}

func (ts *TLSSession) gatherJa3s() bool {
	var buf []byte
	buf = strconv.AppendInt(buf, int64(ts.tlsHdskR.TLSHandshakeServerHello.Vers), 10)
	// byte (44) is ","
	buf = append(buf, byte(44))

	// If there are Cipher Suites
	buf = strconv.AppendInt(buf, int64(ts.tlsHdskR.TLSHandshakeServerHello.CipherSuite), 10)
	buf = append(buf, byte(44))

	// If there are extensions
	if len(ts.tlsHdskR.TLSHandshakeServerHello.AllExtensions) > 0 {
		for i, e := range ts.tlsHdskR.TLSHandshakeServerHello.AllExtensions {
			// TODO check this grease thingy
			if grease[uint16(e)] == false {
				buf = strconv.AppendInt(buf, int64(e), 10)
				if (i + 1) < len(ts.tlsHdskR.TLSHandshakeServerHello.AllExtensions) {
					// byte(45) is "-"
					buf = append(buf, byte(45))
				}
			}
		}
	}

	ts.record.JA3S = string(buf)
	tmp := md5.Sum(buf)
	ts.record.JA3SDigest = hex.EncodeToString(tmp[:])

	return true
}

func (ts *TLSSession) gatherJa3() bool {
	var buf []byte
	buf = strconv.AppendInt(buf, int64(ts.tlsHdskR.TLSHandshakeClientHello.Vers), 10)
	// byte (44) is ","
	buf = append(buf, byte(44))

	// If there are Cipher Suites
	if len(ts.tlsHdskR.TLSHandshakeClientHello.CipherSuites) > 0 {
		for i, cs := range ts.tlsHdskR.TLSHandshakeClientHello.CipherSuites {
			buf = strconv.AppendInt(buf, int64(cs), 10)
			// byte(45) is "-"
			if (i + 1) < len(ts.tlsHdskR.TLSHandshakeClientHello.CipherSuites) {
				buf = append(buf, byte(45))
			}
		}
	}
	buf = append(buf, byte(44))

	// If there are extensions
	if len(ts.tlsHdskR.TLSHandshakeClientHello.AllExtensions) > 0 {
		for i, e := range ts.tlsHdskR.TLSHandshakeClientHello.AllExtensions {
			// TODO check this grease thingy
			if grease[uint16(e)] == false {
				buf = strconv.AppendInt(buf, int64(e), 10)
				if (i + 1) < len(ts.tlsHdskR.TLSHandshakeClientHello.AllExtensions) {
					buf = append(buf, byte(45))
				}
			}
		}
	}
	buf = append(buf, byte(44))

	// If there are Supported Curves
	if len(ts.tlsHdskR.TLSHandshakeClientHello.SupportedCurves) > 0 {
		for i, cs := range ts.tlsHdskR.TLSHandshakeClientHello.SupportedCurves {
			buf = strconv.AppendInt(buf, int64(cs), 10)
			if (i + 1) < len(ts.tlsHdskR.TLSHandshakeClientHello.SupportedCurves) {
				buf = append(buf, byte(45))
			}
		}
	}
	buf = append(buf, byte(44))

	// If there are Supported Points
	if len(ts.tlsHdskR.TLSHandshakeClientHello.SupportedPoints) > 0 {
		for i, cs := range ts.tlsHdskR.TLSHandshakeClientHello.SupportedPoints {
			buf = strconv.AppendInt(buf, int64(cs), 10)
			if (i + 1) < len(ts.tlsHdskR.TLSHandshakeClientHello.SupportedPoints) {
				buf = append(buf, byte(45))
			}
		}
	}
	ts.record.JA3 = string(buf)
	tmp := md5.Sum(buf)
	ts.record.JA3Digest = hex.EncodeToString(tmp[:])
	return true
}

func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	Debug("%s: Connection closed\n", t.ident)
	// do not remove the connection to allow last ACK
	return false
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error
	if *debug {
		outputLevel = 2
	} else if *verbose {
		outputLevel = 1
	} else if *quiet {
		outputLevel = -1
	}
	errorsMap = make(map[string]uint)
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
		// Open live on interface
		if handle, err = pcap.OpenLive(*iface, 65536, true, 0); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
		defer handle.Close()
	}
	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		Info("Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}

	var dec gopacket.Decoder
	var ok bool
	if dec, ok = gopacket.DecodersByLayerName["Ethernet"]; !ok {
		log.Fatal("No eth decoder")
	}
	source := gopacket.NewPacketSource(handle, dec)
	source.Lazy = *lazy
	source.NoCopy = true
	Info("Starting to read packets\n")
	count := 0
	bytes := int64(0)
	defragger := ip4defrag.NewIPv4Defragmenter()

	streamFactory := &tcpStreamFactory{}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	// Signal chan for system signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	// Job chan to hold Completed sessions to write
	jobQ = make(chan TLSSession, 100)
	cancelC := make(chan string)

	// We start a worker to send the processed TLS connection the outside world
	var wg sync.WaitGroup
	go processCompletedSession(jobQ, cancelC, &wg)

	for packet := range source.Packets() {
		count++
		Debug("PACKET #%d\n", count)
		data := packet.Data()
		bytes += int64(len(data))

		// defrag the IPv4 packet if required
		if !*nodefrag {
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ip4Layer == nil {
				continue
			}
			ip4 := ip4Layer.(*layers.IPv4)
			l := ip4.Length
			newip4, err := defragger.DefragIPv4(ip4)
			if err != nil {
				log.Fatalln("Error while de-fragmenting", err)
			} else if newip4 == nil {
				Debug("Fragment...\n")
				continue // ip packet fragment, we don't have whole packet yet.
			}
			if newip4.Length != l {
				stats.ipdefrag++
				Debug("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					panic("Not a PacketBuilder")
				}
				nextDecoder := newip4.NextLayerType()
				nextDecoder.Decode(newip4.Payload, pb)
			}
		}

		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcp := tcp.(*layers.TCP)
			if *checksum {
				err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())
				if err != nil {
					log.Fatalf("Failed to set network layer for checksum: %s\n", err)
				}
			}
			c := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
			}
			stats.totalsz += len(tcp.Payload)
			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
		}
		if count%*statsevery == 0 {
			ref := packet.Metadata().CaptureInfo.Timestamp
			flushed, closed := assembler.FlushWithOptions(reassembly.FlushOptions{T: ref.Add(-timeout), TC: ref.Add(-closeTimeout)})
			Debug("Forced flush: %d flushed, %d closed (%s)", flushed, closed, ref)
		}

		var done bool
		select {
		case <-signalChan:
			fmt.Fprintf(os.Stderr, "\nCaught SIGINT: aborting\n")
			cancelC <- "stop"
			done = true
		default:
			// NOP: continue
		}
		if done {
			break
		}
	}

	assembler.FlushAll()
	streamFactory.WaitGoRoutines()
	wg.Wait()
}

func processCompletedSession(jobQ <-chan TLSSession, cancelC <-chan string, wg *sync.WaitGroup) {
	for {
		select {
		case <-cancelC:
			return
		case tlss := <-jobQ:
			wg.Add(1)
			output(tlss, wg)
		}
	}
}

// Tries to enqueue or false
func queueSession(t TLSSession) bool {
	select {
	case jobQ <- t:
		return true
	default:
		return false
	}
}

func output(t TLSSession, wg *sync.WaitGroup) {

	jsonRecord, _ := json.MarshalIndent(t.record, "", "    ")

	// If an output folder was specified for certificates
	if *outCerts != "" {
		if _, err := os.Stat(fmt.Sprintf("./%s", *outCerts)); !os.IsNotExist(err) {
			for _, cert := range t.record.Certificates {
				go func(cert *x509.Certificate) {
					wg.Add(1)
					err := ioutil.WriteFile(fmt.Sprintf("./%s/%s.crt", *outCerts, t.record.Timestamp.Format(time.RFC3339)), cert.Raw, 0644)
					if err != nil {
						panic("Could not write to file.")
					} else {
						wg.Done()
					}
				}(cert)
			}
		} else {
			panic(fmt.Sprintf("./%s does not exist", *outCerts))
		}
	}

	// If an output folder was specified for json files
	if *outJSON != "" {
		if _, err := os.Stat(fmt.Sprintf("./%s", *outJSON)); !os.IsNotExist(err) {
			go func() {
				wg.Add(1)
				err := ioutil.WriteFile(fmt.Sprintf("./%s/%s.json", *outJSON, t.record.Timestamp.Format(time.RFC3339)), jsonRecord, 0644)
				if err != nil {
					panic("Could not write to file.")
				} else {
					wg.Done()
				}
			}()
		} else {
			panic(fmt.Sprintf("./%s does not exist", *outJSON))
		}
		// If not folder specidied, we output to stdout
	} else {
		r := bytes.NewReader(jsonRecord)
		io.Copy(os.Stdout, r)
	}

	Debug(t.String())
	wg.Done()
}
