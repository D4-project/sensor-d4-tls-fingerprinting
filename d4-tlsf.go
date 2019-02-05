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
var allowmissinginit = flag.Bool("allowmissinginit", false, "Support streams without SYN/SYN+ACK/ACK sequence")
var verbose = flag.Bool("verbose", false, "Be verbose")
var debug = flag.Bool("debug", false, "Display debug information")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")

// capture
var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")

// decoding
//var LayerTypeETLS gopacket.LayerType

// writing
var outCerts = flag.String("w", "", "Folder to write certificates into")
var outJSON = flag.String("j", "", "Folder to write certificates into, stdin if not set")
var jobQ chan d4tls.TLSSession

const closeTimeout time.Duration = time.Hour * 24 // Closing inactive: TODO: from CLI
const timeout time.Duration = time.Minute * 5     // Pending bytes: TODO: from CLI

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
		tlsSession: d4tls.TLSSession{},
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
	tlsSession     d4tls.TLSSession
	sync.Mutex
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		Error("FSM", "%s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
		if !t.fsmerr {
			t.fsmerr = true
		}
		if !*ignorefsmerr {
			return false
		}
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		Error("OptionChecker", "%s: Packet rejected by OptionChecker: %s\n", t.ident, err)
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
	return accept
}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	_, _, _, skip := sg.Info()
	length, _ := sg.Lengths()
	if skip == -1 && *allowmissinginit {
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
					for _, tlsrecord := range tls.Handshake {
						switch tlsrecord.ETLSHandshakeMsgType {
						// Client Hello
						case 1:
							info := sg.CaptureInfo(0)
							cip, sip, cp, sp := getIPPorts(t)
							t.tlsSession.PopulateClientHello(tlsrecord.ETLSHandshakeClientHello, cip, sip, cp, sp, info.Timestamp)
							t.tlsSession.D4Fingerprinting("ja3")
						// Server Hello
						case 2:
							t.tlsSession.PopulateServerHello(tlsrecord.ETLSHandshakeServerHello)
							t.tlsSession.D4Fingerprinting("ja3s")
						// Server Certificate
						case 11:
							t.tlsSession.PopulateCertificate(tlsrecord.ETLSHandshakeCertificate)

							t.tlsSession.D4Fingerprinting("tlsh")
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
	jobQ = make(chan d4tls.TLSSession, 100)
	cancelC := make(chan string)

	// We start a worker to send the processed TLS connection the outside world
	var w sync.WaitGroup
	w.Add(1)
	go processCompletedSession(jobQ, &w)

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

	// All systems gone
	// We close the processing queue
	close(jobQ)
	w.Wait()
}

func processCompletedSession(jobQ <-chan d4tls.TLSSession, w *sync.WaitGroup) {
	for {
		tlss, more := <-jobQ
		if more {
			output(tlss)
		} else {
			w.Done()
			return
		}
	}
}

// Tries to enqueue or false
func queueSession(t d4tls.TLSSession) bool {
	select {
	case jobQ <- t:
		return true
	default:
		return false
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
		// If not folder specidied, we output to stdout
	} else {
		r := bytes.NewReader(jsonRecord)
		_, err := io.Copy(os.Stdout, r)
		if err != nil {
			panic("Could not write to stdout.")
		}
	}

	Debug(t.String())
}
