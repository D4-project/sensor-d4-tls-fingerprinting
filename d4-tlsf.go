package main

import (
	"bytes"

	// TODO consider
	//"github.com/google/certificate-transparency-go/x509"

	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"

	"github.com/D4-project/sensor-d4-tls-fingerprinting/d4tls"
	"github.com/D4-project/sensor-d4-tls-fingerprinting/etls"
)

var nodefrag = flag.Bool("nodefrag", false, "If true, do not do IPv4 defrag")
var checksum = flag.Bool("checksum", false, "Check TCP checksum")
var nooptcheck = flag.Bool("nooptcheck", false, "Do not check TCP options (useful to ignore MSS on captures with TSO)")
var ignorefsmerr = flag.Bool("ignorefsmerr", false, "Ignore TCP FSM errors")
var verbose = flag.Bool("verbose", false, "Be verbose")
var debug = flag.Bool("debug", false, "Display debug information")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")
var partial = flag.Bool("partial", true, "Output partial TLS Sessions, e.g. where we don't see all three of client hello, server hello and certificate")

// capture
var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")

// writing
var outCerts = flag.String("w", "", "Folder to write certificates into")
var outJSON = flag.String("j", "", "Folder to write certificates into, stdin if not set")
var jobQ chan d4tls.TLSSession

// memory
var bufferedPagesPerConnection = flag.Int("mbpc", 16, "Max Buffered Pages per Connection.")
var bufferedPagesTotal = flag.Int("mbpt", 1024, "Max Total Buffered Pages.")

const closeTimeout time.Duration = time.Hour * 24 // Closing inactive: TODO: from CLI
const timeout time.Duration = time.Minute * 5     // Pending bytes: TODO: from CLI

var assemblerOptions = reassembly.AssemblerOptions{
	MaxBufferedPagesPerConnection: *bufferedPagesPerConnection,
	MaxBufferedPagesTotal:         *bufferedPagesTotal, // unlimited
}

var outputLevel int
var errorsMap map[string]uint
var errorsMapMutex sync.Mutex
var errors uint

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
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: true,
	}
	stream := &tcpStream{
		net:        net,
		transport:  transport,
		isTLS:      true,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		optchecker: reassembly.NewTCPOptionCheck(),
		tlsSession: d4tls.TLSSession{},
	}

	// Set network information in the TLSSession
	cip, sip, cp, sp := getIPPorts(stream)
	stream.tlsSession.SetNetwork(cip, sip, cp, sp)

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
	tlsSession     d4tls.TLSSession
	queued         bool
	ignorefsmerr   bool
	nooptcheck     bool
	checksum       bool
	sync.Mutex
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		if !t.fsmerr {
			t.fsmerr = true
		}
		if !t.ignorefsmerr {
			return false
		}
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		if !t.nooptcheck {
			return false
		}
	}
	// Checksum
	accept := true
	if t.checksum {
		c, err := tcp.ComputeChecksum()
		if err != nil {
			accept = false
		} else if c != 0x0 {
			accept = false
		}
	}
	return accept
}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	_, _, _, skip := sg.Info()
	length, _ := sg.Lengths()
	if skip == -1 {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}
	data := sg.Fetch(length)
	if t.isTLS {

		if length > 0 {
			// We attempt to decode TLS
			tls := &etls.ETLS{}
			var decoded []gopacket.LayerType
			p := gopacket.NewDecodingLayerParser(etls.LayerTypeETLS, tls)
			p.DecodingLayerParserOptions.IgnoreUnsupported = true
			err := p.DecodeLayers(data, &decoded)
			if err != nil {
				// If it's fragmented we keep for next round
				sg.KeepFrom(0)
			} else {
				//Debug("TLS: %s\n", gopacket.LayerDump(tls))
				//		Debug("TLS: %s\n", gopacket.LayerGoString(tls))
				if tls.Handshake != nil {

					// If the timestamp has not been set, we set it for the first time.
					if t.tlsSession.Record.Timestamp.IsZero() {
						info := sg.CaptureInfo(0)
						t.tlsSession.SetTimestamp(info.Timestamp)
					}

					for _, tlsrecord := range tls.Handshake {
						switch tlsrecord.ETLSHandshakeMsgType {
						// Client Hello
						case 1:
							t.tlsSession.PopulateClientHello(tlsrecord.ETLSHandshakeClientHello)
							t.tlsSession.D4Fingerprinting("ja3")
						// Server Hello
						case 2:
							t.tlsSession.PopulateServerHello(tlsrecord.ETLSHandshakeServerHello)
							t.tlsSession.D4Fingerprinting("ja3s")
						// Server Certificate
						case 11:
							t.tlsSession.PopulateCertificate(tlsrecord.ETLSHandshakeCertificate)
							t.tlsSession.D4Fingerprinting("tlsh")
						}
					}

					// If the handshake is considered finished and we have not yet outputted it we ship it to output.
					if t.tlsSession.HandshakeComplete() && !t.queued {
						t.queueSession()
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

func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	// If the handshakre has not yet been outputted, but there are some information such as
	// either the client hello or the server hello, we also output a partial.
	if *partial && !t.queued && t.tlsSession.HandshakeAny() {
		t.queueSession()
	}

	// remove connection from the pool
	return true
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

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.NoCopy = true
	Info("Starting to read packets\n")
	count := 0
	bytes := int64(0)
	defragger := ip4defrag.NewIPv4Defragmenter()

	streamFactory := &tcpStreamFactory{}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)
	assembler.AssemblerOptions = assemblerOptions

	// Signal chan for system signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	// Job chan to hold Completed sessions to write
	jobQ = make(chan d4tls.TLSSession, 4096)
	cancelC := make(chan string)

	// We start a worker to send the processed TLS connection the outside world
	var w sync.WaitGroup
	w.Add(1)
	go processCompletedSession(cancelC, jobQ, &w)

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6)
	decoded := []gopacket.LayerType{}

	for packet := range source.Packets() {
		count++
		Debug("PACKET #%d\n", count)

		data := packet.Data()

		if err := parser.DecodeLayers(data, &decoded); err != nil {
			// Well it sures complaing about not knowing how to decode TCP
		}

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				//fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
			case layers.LayerTypeIPv4:
				//fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
				// defrag the IPv4 packet if required
				if !*nodefrag {
					l := ip4.Length
					newip4, err := defragger.DefragIPv4(&ip4)
					if err != nil {
						log.Fatalln("Error while de-fragmenting", err)
					} else if newip4 == nil {
						Debug("Fragment...\n")
						continue // ip packet fragment, we don't have whole packet yet.
					}
					if newip4.Length != l {
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
					assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
				}
				//ref := packet.Metadata().CaptureInfo.Timestamp
				//flushed, closed := assembler.FlushWithOptions(reassembly.FlushOptions{T: ref.Add(time.Minute * 30), TC: ref.Add(time.Minute * 5)})
				//Debug("Forced flush: %d flushed, %d closed (%s)", flushed, closed, ref)
			}
		}

		bytes += int64(len(data))

		var done bool
		select {
		case <-signalChan:
			fmt.Fprintf(os.Stderr, "\nCaught SIGINT: aborting\n")
			cancelC <- "stop"
			done = true
			break
		default:
			// NOP: continue
		}
		if done {
			break
		}
	}

	Info(fmt.Sprintf("%d Bytes read.\n", bytes))

	assembler.FlushAll()
	streamFactory.WaitGoRoutines()

	// All systems gone
	// We close the processing queue
	close(jobQ)
	w.Wait()
}

// queueSession tries to enqueue the tlsSession for output
// returns true if it succeeded or false if it failed to publish the
// tlsSession for output
func (t *tcpStream) queueSession() bool {
	t.queued = true
	select {
	case jobQ <- t.tlsSession:
		return true
	default:
		return false
	}
}

func processCompletedSession(cancelC <-chan string, jobQ <-chan d4tls.TLSSession, w *sync.WaitGroup) {
	for {
		select {
		case tlss, more := <-jobQ:
			if more {
				output(tlss)
			} else {
				w.Done()
				return
			}
		case <-cancelC:
			w.Done()
		}
	}
}

func output(t d4tls.TLSSession) {
	jsonRecord, _ := json.MarshalIndent(t.Record, "", "    ")

	// If an output folder was specified for certificates
	if *outCerts != "" {
		if _, err := os.Stat(fmt.Sprintf("./%s", *outCerts)); !os.IsNotExist(err) {
			for _, certMe := range t.Record.Certificates {
				err := ioutil.WriteFile(fmt.Sprintf("./%s/%s.crt", *outCerts, certMe.CertHash), certMe.Certificate.Raw, 0644)
				if err != nil {
					panic("Could not write to file.")
				}
			}
		} else {
			panic(fmt.Sprintf("./%s does not exist", *outCerts))
		}
	}

	// If an output folder was specified for json files
	if *outJSON != "" {
		if _, err := os.Stat(fmt.Sprintf("./%s", *outJSON)); !os.IsNotExist(err) {
			err := ioutil.WriteFile(fmt.Sprintf("./%s/%s.json", *outJSON, t.Record.Timestamp.Format(time.RFC3339)), jsonRecord, 0644)
			if err != nil {
				panic("Could not write to file.")
			}
		} else {
			panic(fmt.Sprintf("./%s does not exist", *outJSON))
		}
		// If not folder specified, we output to stdout
	} else {
		var buf bytes.Buffer
		if err := json.Compact(&buf, jsonRecord); err != nil {
			fmt.Println("Failed to compact json output")
		}
		if _, err := buf.Write([]byte{0x0A}); err != nil {
			fmt.Println("Could not append delimiter")
		}

		if _, err := io.Copy(os.Stdout, &buf); err != nil {
			panic("Could not write to stdout.")
		}
	}

	Debug(t.String())
}
