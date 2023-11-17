package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"

	"github.com/breml/bpfutils"
)

const (
	iface_name       string         = "wlp1s0"
	iface_ip         string         = "192.168.69.204"
	dst_port         layers.TCPPort = 53
	DNS_PAYLOAD_SIZE uint16         = 54
	ip_filepath      string         = "test_ip1"
)

var wg sync.WaitGroup
var raw_con *ipv4.RawConn

type stop struct{}

var stop_chan = make(chan stop) // (〃・ω・〃)
var ip_chan = make(chan net.IP, 1024)

type TCP_flags struct {
	FIN, SYN, RST, PSH, ACK bool
}

type scan_data_item struct {
	id        uint64
	ts        int64
	ip        net.IP
	port      layers.TCPPort
	seq       uint32
	ack       uint32
	flags     TCP_flags
	dns_recs  []net.IP
	following *scan_data_item
}

type scan_item_key struct {
	port layers.TCPPort
	seq  uint32
}
type root_scan_data struct {
	mu    sync.Mutex
	items map[scan_item_key]scan_data_item
}

func (cur_scan_data *root_scan_data) contains(seq uint32, port layers.TCPPort) bool {
	pos_keys := []scan_item_key{{port, seq}}
	for _, pos_key := range pos_keys {
		_, ok := cur_scan_data.items[pos_key]
		if ok {
			return true
		}
	}
	return false
}

var scan_data root_scan_data

func handle_pkt(pkt gopacket.Packet) {
	log.Println(pkt)
}

func packet_capture(handle *pcapgo.EthernetHandle) {
	defer wg.Done()
	log.Println("starting packet capture")

	/*for {
		pkt_data, ci, err := handle.ReadPacketData()
		if err == io.EOF {
			log.Println("reached EOF")
			break
		}
		if err != nil {
			panic(err)
		}
		go handle_pkt(pkt_data, ci)
	}
	log.Println("stopped packet capture")*/
	pkt_src := gopacket.NewPacketSource(
		handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case pkt := <-pkt_src:
			// kowalski, analysis
			handle_pkt(pkt)
			break
		case <-stop_chan:
			log.Println("stopping packet capture")
			return
		}
	}
}

func send_syn(id uint64, dst_ip net.IP, port layers.TCPPort) {
	ip_hash := sha256.New()
	ip_hash.Write([]byte(dst_ip))
	hash_sum := ip_hash.Sum(nil)
	log.Println(dst_ip, "hash=", hex.EncodeToString(hash_sum))
	// generate sequence number based on first two bytes of ip hash
	seq := uint32(hash_sum[0])<<10 + uint32(hash_sum[1])<<18
	log.Println(dst_ip, "seq_num=", seq)
	// check for sequence number collisions
	scan_data.mu.Lock()
	for scan_data.contains(seq, port) {
		seq += 420
	}
	s_d_item := scan_data_item{
		id:   id,
		ts:   time.Now().Unix(),
		ip:   dst_ip,
		port: port,
		seq:  seq,
		ack:  0,
		flags: TCP_flags{
			FIN: false,
			ACK: false,
			RST: false,
			PSH: false,
			SYN: true,
		},
		dns_recs:  nil,
		following: nil,
	}
	log.Println("scan_data=", s_d_item)
	scan_data.items[scan_item_key{port, seq}] = s_d_item
	scan_data.mu.Unlock()

	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: port,
		DstPort: 53,
		SYN:     true,
		Seq:     seq,
		Ack:     0,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	// qst := layers.DNSQuestion{
	//     Name:  []byte{'w', 'w', 'w', '.', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', '.'},
	//     Type:  layers.DNSTypeCNAME,
	//     Class: layers.DNSClassIN,
	// }

	// dns := layers.DNS{
	//     BaseLayer:    layers.BaseLayer{},
	//     ID:           0,
	//     QR:           true,
	//     OpCode:       0,
	//     AA:           false,
	//     TC:           false,
	//     RD:           true,
	//     RA:           true,
	//     Z:            0,
	//     ResponseCode: 0,
	//     QDCount:      1,
	//     ANCount:      1,
	//     NSCount:      0,
	//     ARCount:      0,
	//     Questions:    []layers.DNSQuestion{qst},
	// }

	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	ip_head_buf := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(ip_head_buf, opts)
	if err != nil {
		panic(err)
	}
	ip_head, err := ipv4.ParseHeader(ip_head_buf.Bytes())
	if err != nil {
		panic(err)
	}

	tcp_buf := gopacket.NewSerializeBuffer()
	//payload := gopacket.Payload([]byte("meowmeowmeow"))
	err = gopacket.SerializeLayers(tcp_buf, opts, &tcp) //, payload)
	if err != nil {
		panic(err)
	}

	fmt.Println("monke never cramps")
	if err = raw_con.WriteTo(ip_head, tcp_buf.Bytes(), nil); err != nil {
		panic(err)
	}
}

type u64id struct {
	mu sync.Mutex
	id uint64
}

var ip_loop_id u64id

func get_next_id() uint64 {
	ip_loop_id.mu.Lock()
	defer ip_loop_id.mu.Unlock()
	ip_loop_id.id += 1
	return ip_loop_id.id
}

func init_tcp() {
	defer wg.Done()
	//dst_ip := net.ParseIP("1.1.1.1")
	port := layers.TCPPort(62003)
	for {
		select {
		case dst_ip := <-ip_chan:
			id := get_next_id()
			send_syn(id, dst_ip, port)
		case <-stop_chan:
			return
		}
	}
}

func read_ips_file() {
	defer wg.Done()
	file, err := os.Open(ip_filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip_chan <- net.ParseIP(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	close(stop_chan)
}

func close_handle(handle *pcapgo.EthernetHandle) {
	defer wg.Done()
	<-stop_chan
	log.Println("closing handle")
	handle.Close()
	log.Println("handle closed")
}

func main() {
	ip_loop_id.id = 0
	scan_data.items = make(map[scan_item_key]scan_data_item)
	// start packet capture
	handle, err := pcapgo.NewEthernetHandle(iface_name) //pcap.OpenLive("wlp1s0", defaultSnapLen, true,
	//pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	iface, err := net.InterfaceByName(iface_name)
	if err != nil {
		panic(err)
	}
	bpf_instr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, iface.MTU, fmt.Sprint("tcp and ip dst ", iface_ip, " and src port 53"))
	var bpf_raw []bpf.RawInstruction
	bpf_raw = bpfutils.ToBpfRawInstructions(bpf_instr)
	if err := handle.SetBPF(bpf_raw); err != nil {
		panic(err)
	}
	// create raw l3 socket
	var pkt_con net.PacketConn
	pkt_con, err = net.ListenPacket("ip4:tcp", iface_ip)
	if err != nil {
		panic(err)
	}
	raw_con, err = ipv4.NewRawConn(pkt_con)
	if err != nil {
		panic(err)
	}

	// start packet capture as goroutine
	wg.Add(3)
	go read_ips_file()
	go packet_capture(handle)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go init_tcp()
	}
	go close_handle(handle)
	wg.Wait()
	log.Println("all routines finished")
	log.Println("program done")
}
