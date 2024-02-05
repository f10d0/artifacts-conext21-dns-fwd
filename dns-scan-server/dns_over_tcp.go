package main

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/ilyakaznacheev/cleanenv"

	"golang.org/x/net/ipv4"

	"github.com/breml/bpfutils"
)

const (
	debug = true
)

// config
type cfg_db struct {
	Iface_name     string `yaml:"iface_name"`
	Iface_ip       string `yaml:"iface_ip"`
	Dst_port       uint16 `yaml:"dst_port"`
	Port_min       uint16 `yaml:"port_min"`
	Port_max       uint16 `yaml:"port_max"`
	Dns_query      string `yaml:"dns_query"`
	Excl_ips_fname string `yaml:"exclude_ips_fname"`
}

var cfg cfg_db

var wg sync.WaitGroup
var raw_con *ipv4.RawConn

type stop struct{}

var stop_chan = make(chan stop) // (〃・ω・〃)
var ip_chan = make(chan net.IP, 1024)

var blocked_nets []*net.IPNet = []*net.IPNet{}

// a simple struct for all the tcp flags needed
type TCP_flags struct {
	FIN, SYN, RST, PSH, ACK bool
}

func (flags TCP_flags) equals(tomatch TCP_flags) bool {
	return flags.FIN == tomatch.FIN &&
		flags.SYN == tomatch.SYN &&
		flags.RST == tomatch.RST &&
		flags.PSH == tomatch.PSH &&
		flags.ACK == tomatch.ACK
}

func (flags TCP_flags) is_PSH_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: false,
		SYN: false,
		RST: false,
		PSH: true,
		ACK: true,
	})
}

func (flags TCP_flags) is_SYN_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: false,
		SYN: true,
		RST: false,
		PSH: false,
		ACK: true,
	})
}

func (flags TCP_flags) is_FIN_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: true,
		SYN: false,
		RST: false,
		PSH: false,
		ACK: true,
	})
}

func (flags TCP_flags) is_FIN_PSH_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: true,
		SYN: false,
		RST: false,
		PSH: true,
		ACK: true,
	})
}

var DNS_PAYLOAD_SIZE uint16

var waiting_to_end = false

/*	id:
*	(seq-num)		(Ports from 61440)   	(2048 byte padding)
*	2^32	*			2^11			/			 2^11		=2^32
*
*	increment: |y=11*x | z=21*x|
*	seq_num = z*2^11, max:2^32-2^11
*	port = y+15<<15 = y+61440
 */

// this struct contains all relevant data to track the tcp connection
type scan_data_item struct {
	id       uint32
	ts       time.Time
	ip       net.IP
	port     layers.TCPPort
	seq      uint32
	ack      uint32
	flags    TCP_flags
	dns_recs []net.IP
	Next     *scan_data_item
}

func (item *scan_data_item) last() *scan_data_item {
	var cur *scan_data_item = item
	for cur.Next != nil {
		cur = cur.Next
	}
	return cur
}

// key for the map below
type scan_item_key struct {
	port layers.TCPPort
	seq  uint32
}

// map to track tcp connections, key is a tuple of (port, seq)
type root_scan_data struct {
	mu    sync.Mutex
	items map[scan_item_key]*scan_data_item
}

var scan_data root_scan_data = root_scan_data{
	items: make(map[scan_item_key]*scan_data_item),
}

var write_chan = make(chan *scan_data_item, 4096)

func scan_item_to_strarr(scan_item *scan_data_item) []string {
	// transform scan_item into string array for csv writer
	var record []string
	record = append(record, strconv.Itoa(int(scan_item.id)))
	record = append(record, scan_item.ts.Format("2006-01-02 15:04:05.000000"))
	record = append(record, scan_item.ip.String())
	record = append(record, scan_item.port.String())
	record = append(record, strconv.Itoa(int(scan_item.seq)))
	record = append(record, strconv.Itoa(int(scan_item.ack)))
	var flags string
	if scan_item.flags.SYN {
		flags += "S"
	}
	if scan_item.flags.RST {
		flags += "R"
	}
	if scan_item.flags.FIN {
		flags += "F"
	}
	if scan_item.flags.PSH {
		flags += "P"
	}
	if scan_item.flags.ACK {
		flags += "A"
	}
	record = append(record, flags)
	dns_answers := ""
	for i, dns_ip := range scan_item.dns_recs {
		dns_answers += dns_ip.String()
		if i != len(scan_item.dns_recs)-1 {
			dns_answers += ","
		}
	}
	record = append(record, dns_answers)
	return record
}

func write_results() {
	defer wg.Done()
	csvfile, err := os.Create("tcp_results.csv.gz")
	if err != nil {
		panic(err)
	}
	defer csvfile.Close()

	zip_writer := gzip.NewWriter(csvfile)
	defer zip_writer.Close()

	writer := csv.NewWriter(zip_writer)
	writer.Comma = ';'
	defer writer.Flush()

	for {
		select {
		case root_item := <-write_chan:
			scan_item := root_item
			for scan_item != nil {
				writer.Write(scan_item_to_strarr(scan_item))
				scan_item = scan_item.Next
			}
			// remove entry from map
			scan_data.mu.Lock()
			delete(scan_data.items, scan_item_key{root_item.port, root_item.seq})
			scan_data.mu.Unlock()
		case <-stop_chan:
			return
		}
	}
}

// periodically remove keys (=connections) that get no response from map
func timeout() {
	defer wg.Done()
	for {
		select {
		case <-time.After(10 * time.Second):
			//go through map's keyset
			scan_data.mu.Lock()
			for k, v := range scan_data.items {
				//remove each key where its timestamp is older than x seconds
				if time.Now().Unix()-v.ts.Unix() > 10 {
					delete(scan_data.items, k)
				}
			}
			scan_data.mu.Unlock()
		case <-stop_chan:
			return
		}
	}
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

func build_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32) (layers.IPv4, layers.TCP, []byte) {
	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       1,
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: src_port,
		DstPort: layers.TCPPort(cfg.Dst_port),
		ACK:     true,
		PSH:     true,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  8192,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	// create dns layers
	qst := layers.DNSQuestion{
		Name:  []byte(cfg.Dns_query),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}
	dns := layers.DNS{
		Questions: []layers.DNSQuestion{qst},
		RD:        true,
		QDCount:   1,
		OpCode:    layers.DNSOpCodeQuery,
		ID:        uint16(rand.Intn(65536)),
	}

	dns_buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(dns_buf, gopacket.SerializeOptions{}, &dns)
	// prepend dns payload with its size, as gopacket does not do this automatically
	dns_buf_bytes := dns_buf.Bytes()
	dns_corrected := make([]byte, len(dns_buf_bytes)+2)
	dns_corrected[0] = uint8(0)
	dns_corrected[1] = uint8(len(dns_buf_bytes))
	for i := 0; i < len(dns_buf_bytes); i++ {
		dns_corrected[i+2] = dns_buf_bytes[i]
	}
	return ip, tcp, dns_corrected
}

func send_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32) {
	send_tcp_pkt(build_ack_with_dns(dst_ip, src_port, seq_num, ack_num))
}

func send_ack_pos_fin(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32, fin bool) {
	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       1,
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: src_port,
		DstPort: layers.TCPPort(cfg.Dst_port),
		ACK:     true,
		FIN:     fin,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  8192,
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	send_tcp_pkt(ip, tcp, nil)
}

func handle_pkt(pkt gopacket.Packet) {
	ip_layer := pkt.Layer(layers.LayerTypeIPv4)
	if ip_layer == nil {
		return
	}
	ip, ok := ip_layer.(*layers.IPv4)
	if !ok {
		return
	}

	tcp_layer := pkt.Layer(layers.LayerTypeTCP)
	if tcp_layer == nil {
		return
	}
	tcp, ok := tcp_layer.(*layers.TCP)
	if !ok { // skip wrong packets
		return
	}
	tcpflags := TCP_flags{
		PSH: tcp.PSH,
		FIN: tcp.FIN,
		SYN: tcp.SYN,
		RST: tcp.RST,
		ACK: tcp.ACK,
	}
	if pkt.ApplicationLayer() == nil {
		// SYN-ACK
		if tcpflags.is_SYN_ACK() {
			if debug {
				log.Println("received SYN-ACK")
			}
			// check if item in map and assign value
			scan_data.mu.Lock()
			root_data_item, ok := scan_data.items[scan_item_key{tcp.DstPort, tcp.Ack - 1}]
			scan_data.mu.Unlock()
			if !ok {
				return
			}
			last_data_item := root_data_item.last()
			// this should not occur, this would be the case if a syn-ack is being received more than once
			if last_data_item != root_data_item {
				return
			}
			data := scan_data_item{
				id:   last_data_item.id,
				ts:   time.Now(),
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
			last_data_item.Next = &data
			send_ack_with_dns(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack)
		} else
		// FIN-ACK
		if tcpflags.is_FIN_ACK() {
			if debug {
				log.Println("received FIN-ACK")
			}
			scan_data.mu.Lock()
			root_data_item, ok := scan_data.items[scan_item_key{tcp.DstPort, tcp.Ack - 2 - uint32(DNS_PAYLOAD_SIZE)}]
			scan_data.mu.Unlock()
			if !ok {
				return
			}

			last_data_item := root_data_item.last()
			if !(last_data_item.flags.is_PSH_ACK()) {
				if debug {
					log.Println("missing PSH-ACK, dropping")
				}
				// to do this properly in theory, we would also need to send a FIN-ACK back to the server here,
				// because the connection we once established still remains intact and the remote server is asking to terminate it
				send_ack_pos_fin(ip.SrcIP, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				// TODO now we could check if the correct key ACK-(1+DNS_PAYLOAD_SIZE) exists and remove that one from the dictionary
				return
			}
			if debug {
				log.Println("ACKing FIN-ACK")
			}
			send_ack_pos_fin(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack, false)
			write_chan <- root_data_item
		}
	} else
	// PSH-ACK || FIN-PSH-ACK == DNS Response
	if tcpflags.is_PSH_ACK() || tcpflags.is_FIN_PSH_ACK() {
		// TODO there is the case where some dns servers tend to respond to the initial query
		// only after a very long time (more than 120 seconds)
		// meanwhile they send keep-alive packets (with what seems like exponentially increasing delay)
		// I'm not yet sure if we should handle this case
		// this would mean updating the timeout to not trigger the keys removal from the map
		// if we dont handle this case though, maybe we should sent out FIN-ACKs which we would have to respond to with an ACK
		// which is a bit difficult as we dont really know if the receiving FIN-ACKs are in response to ours or self-initiated (or just RSTs)
		// if we dont terminate the connection it might interfere with another newly established connection

		if debug {
			log.Println("received PSH-ACK or FIN-PSH-ACK")
		}
		// decode as DNS Packet
		dns := &layers.DNS{}
		// remove the first two bytes of the payload, i.e. size of the dns response
		// see build_ack_with_dns()
		if len(tcp.LayerPayload()) <= 2 {
			//TODO this could be the point where we handle the keep-alive pkt
			return
		}
		// validate payload size
		pld_size := int(tcp.LayerPayload()[0]) + int(tcp.LayerPayload()[1])<<8
		if pld_size == len(tcp.LayerPayload())-2 {
			return
		}
		pld := make([]byte, len(tcp.LayerPayload())-2)
		for i := 0; i < len(pld); i++ {
			pld[i] = tcp.LayerPayload()[i+2]
		}
		err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
		if err != nil {
			if debug {
				log.Println("DNS not found")
			}
			return
		}
		if debug {
			log.Println("got DNS response")
		}
		// check if item in map and assign value
		scan_data.mu.Lock()
		root_data_item, ok := scan_data.items[scan_item_key{tcp.DstPort, tcp.Ack - 1 - uint32(DNS_PAYLOAD_SIZE)}]
		scan_data.mu.Unlock()
		if !ok {
			return
		}
		last_data_item := root_data_item.last()
		// this should not occur, this would be the case if a psh-ack is being received more than once
		if last_data_item.flags.is_PSH_ACK() {
			if debug {
				log.Println("already received PSH-ACK")
			}
			return
		}
		if !(last_data_item.flags.is_SYN_ACK()) {
			if debug {
				log.Println("missing SYN-ACK")
			}
			return
		}
		answers := dns.Answers
		var answers_ip []net.IP
		for _, answer := range answers {
			if answer.IP != nil {
				answers_ip = append(answers_ip, answer.IP)
				if debug {
					log.Println(answer.IP)
				}
			} else {
				if debug {
					log.Println("non IP type found in answer")
				}
				return
			}
		}
		data := scan_data_item{
			id:   last_data_item.id,
			ts:   time.Now(),
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
			dns_recs: answers_ip,
		}
		last_data_item.Next = &data
		// send FIN-ACK to server
		send_ack_pos_fin(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
		// if this pkt is fin-psh-ack we will remove it from the map at this point already
		// because we wont receive any further fin-ack from the server
		if tcpflags.is_FIN_PSH_ACK() {
			write_chan <- root_data_item
		}
	}
}

func packet_capture(handle *pcapgo.EthernetHandle) {
	defer wg.Done()
	if debug {
		log.Println("starting packet capture")
	}
	pkt_src := gopacket.NewPacketSource(
		handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case pkt := <-pkt_src:
			go handle_pkt(pkt)
		case <-stop_chan:
			if debug {
				log.Println("stopping packet capture")
			}
			return
		}
	}
}

func send_syn(id uint32, dst_ip net.IP) {
	// generate sequence number based on the first 21 bits of the hash
	seq := (id & 0x1FFFFF) * 2048
	port := layers.TCPPort(((id & 0xFFE00000) >> 21) + 61440)
	if debug {
		log.Println(dst_ip, "seq_num=", seq)
	}
	// check for sequence number collisions
	scan_data.mu.Lock()
	s_d_item := scan_data_item{
		id:   id,
		ts:   time.Now(),
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
		Next:     nil,
	}
	if debug {
		log.Println("scan_data=", s_d_item)
	}
	scan_data.items[scan_item_key{port, seq}] = &s_d_item
	scan_data.mu.Unlock()

	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       1,
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

type u32id struct {
	mu sync.Mutex
	id uint32
}

// id for saving to results file, synced between multiple init_tcp()
var ip_loop_id u32id = u32id{
	id: 0,
}

func get_next_id() uint32 {
	ip_loop_id.mu.Lock()
	defer ip_loop_id.mu.Unlock()
	ip_loop_id.id += 1
	return ip_loop_id.id
}

func init_tcp(port_min uint16, port_max uint16) {
	defer wg.Done()
	for {
		select {
		case dst_ip := <-ip_chan:
			// check for if ip is excluded in the blocklist
			should_exclude := false
			for _, blocked_net := range blocked_nets {
				if blocked_net.Contains(dst_ip) {
					should_exclude = true
					break
				}
			}
			if should_exclude {
				if debug {
					log.Println("excluding ip:", dst_ip)
				}
				continue
			}
			id := get_next_id()
			if debug {
				log.Println("ip:", dst_ip, id)
			}
			send_syn(id, dst_ip)
		case <-stop_chan:
			return
		}
	}
}

func read_ips_file(fname string) {
	defer wg.Done()
	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		ip_chan <- net.ParseIP(line)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just read
	if debug {
		log.Println("read all ips, waiting to end ...")
	}
	waiting_to_end = true
	time.Sleep(10 * time.Second)
	close(stop_chan)
}

func close_handle(handle *pcapgo.EthernetHandle) {
	defer wg.Done()
	<-stop_chan
	if debug {
		log.Println("closing handle")
	}
	handle.Close()
	if debug {
		log.Println("handle closed")
	}
}

func load_config() {
	err := cleanenv.ReadConfig("config.yml", &cfg)
	if err != nil {
		panic(err)
	}
	if debug {
		log.Println("config:", cfg)
	}
}

func write_to_log(msg string) {
	logfile, err := os.OpenFile("run.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	defer logfile.Close()
	logfile.WriteString(msg + "\n")
}

// Linear Congruential Generator
// as described in https://stackoverflow.com/a/53551417
type lcg_state struct {
	value      int
	offset     int
	multiplier int
	modulus    int
	max        int
	found      int
}

var lcg_ipv4 lcg_state

func (lcg *lcg_state) init(stop int) {
	// Seed range with a random integer.
	lcg.value = rand.Intn(stop)
	lcg.offset = rand.Intn(stop)*2 + 1                                  // Pick a random odd-valued offset.
	lcg.multiplier = 4*(int(stop/4)) + 1                                // Pick a multiplier 1 greater than a multiple of 4
	lcg.modulus = int(math.Pow(2, math.Ceil(math.Log2(float64(stop))))) // Pick a modulus just big enough to generate all numbers (power of 2)
	lcg.found = 0                                                       // Track how many random numbers have been returned
	lcg.max = stop
}

func (lcg *lcg_state) next() int {
	for lcg.value >= lcg.max {
		lcg.value = (lcg.value*lcg.multiplier + lcg.offset) % lcg.modulus
	}
	lcg.found += 1
	value := lcg.value
	// Calculate the next value in the sequence.
	lcg.value = (lcg.value*lcg.multiplier + lcg.offset) % lcg.modulus
	return value
}

func (lcg *lcg_state) has_next() bool {
	return lcg.found < lcg.max
}

func ip42uint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func uint322ip(ipint uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipint)
	return ip
}

func gen_ips(netip net.IP, hostsize int) {
	defer wg.Done()
	netip_int := ip42uint32(netip)
	lcg_ipv4.init(int(math.Pow(2, float64(hostsize))))
	for lcg_ipv4.has_next() {
		val := lcg_ipv4.next()
		ip_chan <- uint322ip(netip_int + uint32(val))
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just read
	if debug {
		log.Println("all ips generated, waiting to end ...")
	}
	waiting_to_end = true
	time.Sleep(10 * time.Second)
	close(stop_chan)
}

func exclude_ips() {
	if _, err := os.Stat(cfg.Excl_ips_fname); errors.Is(err, os.ErrNotExist) {
		if debug {
			log.Println("ip exclusion list not found, skipping")
			log.Println("exclusion list filename was read as:", cfg.Excl_ips_fname)
		}
		return
	}
	file, err := os.Open(cfg.Excl_ips_fname)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		comment_pos := strings.IndexByte(line, '#')
		if comment_pos == -1 {
			comment_pos = len(line)
		}
		pos_net := line[:comment_pos]
		pos_net = strings.TrimSpace(pos_net)
		if pos_net == "" {
			continue
		}
		_, new_net, err := net.ParseCIDR(pos_net)
		if err != nil { // if there are errors try if the string maybe is a single ip
			toblock_ip := net.ParseIP(pos_net)
			if toblock_ip == nil {
				log.Println("could not interpret line, skipping")
				continue
			}
			mask := net.CIDRMask(32, 32) // 32 bits for IPv4
			new_net = &net.IPNet{IP: toblock_ip, Mask: mask}
		}

		blocked_nets = append(blocked_nets, new_net)
		if debug {
			log.Println("added blocked net:", new_net.String())
		}
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

func main() {
	// TODO run iptables command so that kernel doesnt send out RSTs
	// sudo iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP > /dev/null || sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

	// write start ts to log
	write_to_log("START " + time.Now().UTC().String())
	// command line args
	if len(os.Args) < 1 {
		write_to_log("END " + time.Now().UTC().String() + " arg not given")
		if debug {
			log.Println("ERR need filename or net in CIDR notation")
		}
		return
	}
	ip_or_file_split := strings.Split(os.Args[1], "/")
	var fname string
	var netip net.IP
	var hostsize int
	if len(ip_or_file_split) == 1 {
		// using filename
		fname = ip_or_file_split[0]
	} else if len(ip_or_file_split) == 2 {
		// using CIDR net
		netip = net.ParseIP(ip_or_file_split[0])
		var err error
		hostsize, err = strconv.Atoi(ip_or_file_split[1])
		if err != nil {
			panic(err)
		}
		hostsize = 32 - hostsize
	} else {
		write_to_log("END " + time.Now().UTC().String() + " wrongly formatted input arg")
		if debug {
			log.Println("ERR check your input arg (filename or CIDR notation)")
		}
	}

	// handle ctrl+c SIGINT
	go func() {
		interrupt_chan := make(chan os.Signal, 1)
		signal.Notify(interrupt_chan, os.Interrupt)
		<-interrupt_chan
		if waiting_to_end {
			if debug {
				log.Println("already ending")
			}
		} else {
			if debug {
				log.Println("received SIGINT, ending")
			}
			close(stop_chan)
		}
	}()

	load_config()
	exclude_ips()
	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := build_ack_with_dns(net.ParseIP("0.0.0.0"), 0, 0, 0)
	DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
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
	if err != nil {
		panic(err)
	}
	bpf_raw := bpfutils.ToBpfRawInstructions(bpf_instr)
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
	wg.Add(5)
	go packet_capture(handle)
	go write_results()
	go timeout()
	if fname != "" {
		if debug {
			log.Println("running in filename mode")
		}
		go read_ips_file(fname)
	} else {
		if debug {
			log.Println("running in CIDR mode")
		}
		go gen_ips(netip, hostsize)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go init_tcp(cfg.Port_min, cfg.Port_max)
	}
	go close_handle(handle)
	wg.Wait()
	if debug {
		log.Println("all routines finished")
	}
	write_to_log("END " + time.Now().UTC().String())
	if debug {
		log.Println("program done")
	}
}
