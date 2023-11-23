package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/ilyakaznacheev/cleanenv"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"

	"github.com/breml/bpfutils"
)

// config
type cfg_db struct {
	Iface_name string `yaml:"iface_name"`
	Iface_ip   string `yaml:"iface_ip"`
	Dst_port   uint16 `yaml:"dst_port"`
	Port_min   uint16 `yaml:"port_min"`
	Port_max   uint16 `yaml:"port_max"`
	Dns_query  string `yaml:"dns_query"`
}

var cfg cfg_db

var wg sync.WaitGroup
var raw_con *ipv4.RawConn

type stop struct{}

var stop_chan = make(chan stop) // (〃・ω・〃)
var ip_chan = make(chan net.IP, 1024)

// a simple struct for all the tcp flags needed
type TCP_flags struct {
	FIN, SYN, RST, PSH, ACK bool
}

const (
	DNS_PAYLOAD_SIZE uint16 = 54
	ip_filepath      string = "test_ip1"
)

// this struct contains all relevant data to track the tcp connection
type scan_data_item struct {
	id       uint64
	ts       int64
	ip       net.IP
	port     layers.TCPPort
	seq      uint32
	ack      uint32
	flags    TCP_flags
	dns_recs []net.IP
	next     *scan_data_item
}

func (item *scan_data_item) last() *scan_data_item {
	if item.next == nil {
		return item
	} else {
		return item.last()
	}
}

// key for the map below
type scan_item_key struct {
	port layers.TCPPort
	seq  uint32
}

// map to track tcp connections, key is a tuple of (port, seq)
type root_scan_data struct {
	mu    sync.Mutex
	items map[scan_item_key]scan_data_item
}

var scan_data root_scan_data

// check whether a map entry with the provided sequence number and tcp port already exists
func (cur_scan_data *root_scan_data) contains(port layers.TCPPort, seq uint32) bool {
	_, ok := cur_scan_data.items[scan_item_key{port, seq}]
	if ok {
		return true
	}
	return false
}

var opts gopacket.SerializeOptions = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

func send_tcp_pkt(ip layers.IPv4, tcp layers.TCP, payload []byte) {
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
	err = gopacket.SerializeLayers(tcp_buf, opts, &tcp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}

	if err = raw_con.WriteTo(ip_head, tcp_buf.Bytes(), nil); err != nil {
		panic(err)
	}
}

func send_tcp_pkt_dns(ip layers.IPv4, tcp layers.TCP, dns layers.DNS) {
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
	err = gopacket.SerializeLayers(tcp_buf, opts, &tcp, &dns)
	if err != nil {
		panic(err)
	}

	if err = raw_con.WriteTo(ip_head, tcp_buf.Bytes(), nil); err != nil {
		panic(err)
	}
}

func send_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32) {
	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: src_port,
		DstPort: layers.TCPPort(cfg.Dst_port),
		ACK:     true,
		PSH:     true,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  512,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	qst := layers.DNSQuestion{
		Name:  []byte(cfg.Dns_query + "."),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}

	// create dns layers
	dns := layers.DNS{
		/*BaseLayer:    layers.BaseLayer{},
		ID:           0, //TODO RNG
		QR:           false,
		OpCode:       0,
		AA:           false,
		TC:           false,
		RD:           true,
		RA:           true,
		Z:            0,
		ResponseCode: 0,
		QDCount:      1,
		ANCount:      1,
		NSCount:      0,
		ARCount:      0,
		Questions:    []layers.DNSQuestion{qst},*/
		Questions: []layers.DNSQuestion{qst},
		RD:        true,
		QDCount:   1,
		OpCode:    layers.DNSOpCodeQuery,
		ANCount:   1,
		QR:        false,
	}

	dns_buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(dns_buf, opts, &dns)
	//send_tcp_pkt(ip, tcp, dns_buf.Bytes())
	send_tcp_pkt_dns(ip, tcp, dns)
}

func handle_pkt(pkt gopacket.Packet) {
	log.Println(pkt)

	ip_layer := pkt.Layer(layers.LayerTypeIPv4)
	ip, ok := ip_layer.(*layers.IPv4)
	if !ok {
		return
	}

	tcp_layer := pkt.Layer(layers.LayerTypeTCP)
	if tcp_layer != nil {
		if pkt.ApplicationLayer() == nil {
			tcp, ok := tcp_layer.(*layers.TCP)
			if !ok { // skip wrong packets
				return
			}
			// SYN-ACK
			if tcp.SYN && tcp.ACK {
				log.Println("received SYN-ACK")
				// check if item in map
				if !scan_data.contains(tcp.DstPort, tcp.Ack-1) {
					return
				}
				root_data_item, _ := scan_data.items[scan_item_key{tcp.DstPort, tcp.Ack - 1}]
				last_data_item := root_data_item.last()
				data := scan_data_item{
					id:   last_data_item.id,
					ts:   time.Now().Unix(),
					port: tcp.DstPort,
					seq:  tcp.Seq,
					ack:  tcp.Ack,
					ip:   ip.SrcIP,
					flags: TCP_flags{
						FIN: tcp.FIN,
						SYN: tcp.SYN,
						RST: tcp.RST,
						PSH: tcp.PSH,
						ACK: tcp.ACK,
					},
				}
				last_data_item.next = &data
				send_ack_with_dns(ip.SrcIP, tcp.DstPort, tcp.Seq, tcp.Ack)
			} else
			// PSH-ACK == DNS Response
			if tcp.PSH && tcp.ACK {
				log.Println("received PSH-ACK")
				// decode as DNS Packet
				dns_layer := pkt.Layer(layers.LayerTypeDNS)
				if dns_layer != nil {
					log.Println("got DNS response")
					dns, ok := dns_layer.(*layers.DNS)
					if !ok {
						return
					}
					log.Println(dns.Answers)
				}
			}
		}
	}
}

func packet_capture(handle *pcapgo.EthernetHandle) {
	defer wg.Done()
	log.Println("starting packet capture")
	pkt_src := gopacket.NewPacketSource(
		handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case pkt := <-pkt_src:
			go handle_pkt(pkt)
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
	// generate sequence number based on first two bytes of ip hash
	seq := uint32(hash_sum[0])<<10 + uint32(hash_sum[1])<<18
	log.Println(dst_ip, "seq_num=", seq)
	// check for sequence number collisions
	scan_data.mu.Lock()
	for scan_data.contains(port, seq) {
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
		dns_recs: nil,
		next:     nil,
	}
	log.Println("scan_data=", s_d_item)
	scan_data.items[scan_item_key{port, seq}] = s_d_item
	scan_data.mu.Unlock()

	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(cfg.Iface_ip),
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

	send_tcp_pkt(ip, tcp, nil)
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

func init_tcp(port_min uint16, port_max uint16) {
	defer wg.Done()
	// choose a random port in the provided range
	port := layers.TCPPort(rand.Intn(int(port_max)-int(port_min)) + int(port_min))
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
	log.Println("read all ips, waiting to end ...")
	time.Sleep(10 * time.Second)
	close(stop_chan)
}

func close_handle(handle *pcapgo.EthernetHandle) {
	defer wg.Done()
	<-stop_chan
	log.Println("closing handle")
	handle.Close()
	log.Println("handle closed")
}

func load_config() {
	err := cleanenv.ReadConfig("config.yml", &cfg)
	if err != nil {
		panic(err)
	}
	log.Println("config:", cfg)
}

func main() {
	load_config()
	ip_loop_id.id = 0
	scan_data.items = make(map[scan_item_key]scan_data_item)
	// start packet capture
	handle, err := pcapgo.NewEthernetHandle(cfg.Iface_name) //pcap.OpenLive("wlp1s0", defaultSnapLen, true,
	//pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	iface, err := net.InterfaceByName(cfg.Iface_name)
	if err != nil {
		panic(err)
	}
	bpf_instr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, iface.MTU, fmt.Sprint("tcp and ip dst ", cfg.Iface_ip, " and src port 53"))
	var bpf_raw []bpf.RawInstruction
	bpf_raw = bpfutils.ToBpfRawInstructions(bpf_instr)
	if err := handle.SetBPF(bpf_raw); err != nil {
		panic(err)
	}
	// create raw l3 socket
	var pkt_con net.PacketConn
	pkt_con, err = net.ListenPacket("ip4:tcp", cfg.Iface_ip)
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
		go init_tcp(cfg.Port_min, cfg.Port_max)
	}
	go close_handle(handle)
	wg.Wait()
	log.Println("all routines finished")
	log.Println("program done")
}