#! /usr/bin/env python3
###############################################################################
# import necessary scapy functions
from scapy.all import *
from scapy.layers.inet import Ether, IP, TCP
from scapy.layers.dns import DNS, DNSQR, DNSRR

# to use command line arguments
from sys import argv
# some time functions for timestamps or delays
from datetime import datetime
from time import sleep
# use thread safe queue to process incoming and outgoing data
from queue import Queue
# get some pseudo random factor
import random
# to load config.ini file
import configparser as cp
# add some colors for output
from colorama import Fore
from colorama import Style

# add process bar
from tqdm import tqdm
import hashlib

import random, math
import socket, struct
import logging

###############################################################################

conf.layers.filter([Ether, IP, TCP, DNS, DNSQR, DNSRR])
conf.layers.unfilter()

class my_colors:
    END = Style.RESET_ALL
    SEND = Fore.GREEN
    RECV = Fore.YELLOW
    INFO = Fore.CYAN
    ERROR = Fore.RED

def ip2long(ip: str) -> int:
    """
    Convert an IP string to long
    """
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

def valid_ip(address: str) -> bool:
    """
    Check whether a string is a valid ip address 
    """
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False

def random_net_range(start, network_part):
    for i in random_range(start=start):
        new_long_ip = i+network_part
        yield(socket.inet_ntoa(struct.pack('!L', new_long_ip)))

def random_ip_range(ip_list):
    for i in range(len(ip_list)):
        yield(ip_list[i])

def random_range(start, stop=None, step=None):
    """
    Linear Congruential Generator
    as seen in https://stackoverflow.com/a/53551417
    """
    # Set a default values the same way "range" does.
    if (stop == None): start, stop = 0, start
    if (step == None): step = 1
    # Use a mapping to convert a standard range into the desired range.
    mapping = lambda i: (i*step) + start
    # Compute the number of numbers in this range.
    maximum = (stop - start) // step
    # Seed range with a random integer.
    value = random.randint(0,maximum)
    offset = random.randint(0,maximum) * 2 + 1      # Pick a random odd-valued offset.
    multiplier = 4*(maximum//4) + 1                 # Pick a multiplier 1 greater than a multiple of 4.
    modulus = int(2**math.ceil(math.log2(maximum))) # Pick a modulus just big enough to generate all numbers (power of 2).
    # Track how many random numbers have been returned.
    found = 0
    while found < maximum:
        # If this is a valid value, yield it in generator fashion.
        if value < maximum:
            found += 1
            yield mapping(value)
        # Calculate the next value in the sequence.
        value = (value*multiplier + offset) % modulus

# Implementation of DNS Measurement
# should be separate from actual implementation
# of DNS (DNS over TCP, DNS over Http etc.)
# this may not be trivial so at first we only
# implement DNS over TCP
class DNS_Over_TCP:
    def __init__(self, debug: bool, process_id: int):
        self.__logger = logging.getLogger("dns_over_tcp")
        if debug:
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)
        # set Ether() layer because it's static
        self.__ether = Ether()
        # list of ip addresses to scan
        self.__ip_list = []
        # stop condition for sniffer
        self.__all_pkts_sent = False
        # read config.ini file (DEFAULT section)
        self.__config = self.read_config(file = "config.ini",section="DEFAULT")
        # split port range
        if id != 0:
            port_min = int(self.__config['portrange_min'])
            port_max = int(self.__config['portrange_max'])
            num_processes = int(self.__config['processes'])
            per_process_r = int((port_max - port_min)/num_processes)
            self.__port_min = port_min + per_process_r*(process_id-1)
            self.__port_max = self.__port_min + per_process_r if self.__port_min + per_process_r < port_max else port_max
        else:
            self.__port_min = int(self.__config['portrange_min'])
            self.__port_max = int(self.__config['portrange_max'])
        # init bpf filter after loading config
        # sniff only on incoming pkts within portrange
        self.__bpf = f"tcp and ip dst {self.__config['ip_client']} "
        self.__bpf += f"and src port {self.__config['dst_port']} "
        self.__bpf += f"and dst portrange {str(self.__port_min)}-{str(self.__port_max)}"
        # list of free ports
        self.__ports = [i for i in range(self.__port_min,self.__port_max)]
        # prefix for the id in scan_data
        self.__process_id = process_id
        # temporary scan data (dictionary with port number and sequence number as key
        # structure: (port, seq_num):[ ( id, timestamp, IP-Adr., Dest. Port, TCP Seqnum, TCP Acknum, TCP Flags, DNS A Records ),... ]
        self.__scan_data = {}
        
        # init queues for answers
        self.__pkt_queue = Queue()
        self.__writeback = Queue()

        self.__scan_thread = Thread(target = self.init_tcp_connections)
        self.__sniffer_thread = Thread(target = self.sniffer)
        self.__process_thread = Thread(target = self.process_responses_thread)
        self.__writeback_thread = Thread(target = self.writeback_thread)
        # make sure to start sniffer thread first
        self.__running_threads = [self.__sniffer_thread, 
                                  self.__scan_thread, 
                                  self.__process_thread,
                                  self.__writeback_thread]
        self.DNS_PAYLOAD_SIZE = len(DNS(rd=1, id=0, qd=DNSQR(qname=self.__config["qry_name"]))) +2 # the size attribute itself is 2 bytes
        self.__s2 = conf.L2socket(iface=self.__config["iface"]) # reuse L2 socket, this will speedup scapy by a lot
        self.__s3 = conf.L3socket() # reuse the same L3 socket

        self.__ip_pkt = IP(src=self.__config["ip_client"], dst="0.0.0.0", ttl=int(self.__config["ttl"]))
        self.__tcp_syn_pkt = TCP(sport=0, dport=int(self.__config["dst_port"]), flags="S",seq=0)

    def start_scanning(self):
        self.__logger.info(f"port range: {str(self.__port_min)} - {str(self.__port_max)}")
        self.__logger.debug(f"berkeley packet filter: {str(self.__bpf)}")
        self.__logger.info(f"{my_colors.INFO}[*] Starting Scan.{my_colors.END}")
        for thread in self.__running_threads:
            thread.start()

    def read_config(self,file,section):
        config = cp.ConfigParser()
        config.read(file)
        return config[section]

    def set_ip_list(self,fname):
        self.__run_mode = "file"
        with open(fname) as ip_list:
            for line in ip_list.readlines():
                if not (line == '' or line.isspace()) and valid_ip(line.rstrip()):
                    self.__ip_list.append(line.rstrip())
        random.shuffle(self.__ip_list)
        self.__logger.debug(f"{my_colors.INFO}[*] Loading IP Addresses Done.")
        self.__logger.debug(f"[*] Head: {self.__ip_list[:5]}{my_colors.END}")
    
    def set_cidr_ip(self, network_ip: str, host_len: int):
        self.__run_mode = "cidr"
        self.__network_ip = network_ip
        self.__host_len = host_len

    def init_tcp_connections(self):
        # main thread which goes through all given ip's
        # and sends syn packets
        if self.__run_mode == "cidr":
            net_ip_as_long = ip2long(self.__network_ip)
            range_used = random_net_range(start=2**self.__host_len, network_part=net_ip_as_long)
        elif self.__run_mode == "file":
            range_used = random_ip_range(self.__ip_list)
        else:
            self.__logger.error("mode error")
            exit(2)

        lc = 0
        for ip in range_used:
            self.__logger.debug(f"cur ip: {ip}")
            port = random.choice(self.__ports)
            # get seq_num based on hash of ip address
            # times 1000 so that the seq nums are far enough apart for tracking the connection
            seq = int.from_bytes(hashlib.sha256(ip.encode("utf-8")).digest()[:2], 'little') * 1000
            # there is a small probability that this sequence number might already be in use due to only taking
            # the first 2 bytes of the ip address hash
            while (port,seq) in self.__scan_data \
                  and (port,seq-1) in self.__scan_data \
                  and (port,seq-1-self.DNS_PAYLOAD_SIZE) in self.__scan_data \
                  and (port,seq-2-self.DNS_PAYLOAD_SIZE) in self.__scan_data:
                seq = seq + 42
            self.__scan_data[(port,seq)] = [(str(self.__process_id)+"_"+str(lc),datetime.utcnow(),ip,port,seq,seq,"S","")]
            lc = lc+1
            self.send_syn_packet(ip, port, seq)
        self.__logger.info(f"{my_colors.INFO}[*] Sending SYN Packets Done.{my_colors.END}")
        sleep(15)
        self.__logger.info(f"{my_colors.INFO}[*] Slowly Shutting Down Scan/Capture Process.{my_colors.END}")
        self.__all_pkts_sent = True
        self.__running_threads.remove(self.__scan_thread)
        self.stop_threads()
        return

    def capture_packets(self,pkt):
        # got syn/ack?
        self.__logger.debug(f"{my_colors.RECV}[*] Captured Packet: {pkt.summary()}{my_colors.END}")
        if (TCP in pkt and not DNS in pkt and \
                int(self.__config["portrange_min"]) <= pkt[TCP].dport <= int(self.__config["portrange_max"]) and \
                pkt[TCP].flags == "SA"):
            self.__pkt_queue.put([datetime.utcnow(),pkt[IP].src,pkt[TCP].dport,pkt[TCP].flags,pkt[TCP].seq,pkt[TCP].ack,None])
        # got dns answer? 
        elif (TCP in pkt and DNS in pkt and \
                int(self.__config["portrange_min"]) <= pkt[TCP].dport <= int(self.__config["portrange_max"])):
            if DNSRR in pkt:
                self.__pkt_queue.put([datetime.utcnow(),pkt[IP].src,pkt[TCP].dport,pkt[TCP].flags,pkt[TCP].seq,pkt[TCP].ack,(pkt[DNSRR],pkt[DNS].ancount),len(pkt[TCP].payload)])
            # got dns answer but no ressource records?
            else:
                self.__pkt_queue.put([datetime.utcnow(),pkt[IP].src,pkt[TCP].dport,pkt[TCP].flags,pkt[TCP].seq,pkt[TCP].ack,("No RR Records in DNS answer",pkt[DNS].ancount),len(pkt[TCP].payload)])
        # got fin/ack?
        elif (TCP in pkt and not DNS in pkt and \
            int(self.__config["portrange_min"]) <= pkt[TCP].dport <= int(self.__config["portrange_max"]) and \
            pkt[TCP].flags == "FA"):
            self.__pkt_queue.put([datetime.utcnow(),pkt[IP].src,pkt[TCP].dport,pkt[TCP].flags,pkt[TCP].seq,pkt[TCP].ack,None])
        # got connection reset? -> write back and free used port (instead of waiting for timer)
        # this is not necessary but may be a little optimization to improve performance
        elif (TCP in pkt and not DNS in pkt and \
            int(self.__config["portrange_min"]) <= pkt[TCP].dport <= int(self.__config["portrange_max"]) and \
            pkt[TCP].flags == "R"):
            self.__pkt_queue.put([datetime.utcnow(),pkt[IP].src,pkt[TCP].dport,pkt[TCP].flags,pkt[TCP].seq,pkt[TCP].ack,None])
        # ignore other answer types for now
        else:
            pass

    def process_responses_thread(self):
        while not self.__all_pkts_sent:
            # process queue with responses
            # queue is thread safe
            data = self.__pkt_queue.get()
            self.__logger.debug(f"{my_colors.INFO}[*] Got data in queue: {data}{my_colors.END}")
            self.process_packet_data(data)
        self.__logger.info(f"{my_colors.INFO}[*] Processing responses is about to end...emptying queue.{my_colors.END}")
        # empty queue
        while not self.__pkt_queue.empty():
            self.process_packet_data(self.__pkt_queue.get())
        self.__logger.info(f"{my_colors.INFO}[*] Processing responses done.{my_colors.END}")
        # writeback queue stays blocked -> free it by filling it with a dummy port, all ports should be empty by now
        # so we can use whatever port we want
        #self.__writeback.put((10000,10000))
        return

    def process_packet_data(self,data):
        # definition of data:
        # Index: 0             1               2           3          4           5                       6
        # [ timestamp, Source IP-Address, Dest. Port, TCP Flags, TCP Seqnum, TCP Acknum, (DNS Res. Records, DNS Answer Count) ]
        
        ack_num = data[5]
        # load packet history
        # SYN-ACK
        if (data[2],ack_num-1) in self.__scan_data.keys():
            syn_num = ack_num-1
        # DNS Response
        elif (data[2],ack_num-1-self.DNS_PAYLOAD_SIZE) in self.__scan_data.keys():
            syn_num = ack_num-1-self.DNS_PAYLOAD_SIZE
        # FIN-ACK
        elif (data[2],ack_num-2-self.DNS_PAYLOAD_SIZE) in self.__scan_data.keys():
            syn_num = ack_num-2-self.DNS_PAYLOAD_SIZE
        else:
            return

        history = self.__scan_data[(data[2],syn_num)]

        #drop all without history (malformed dns warning)
        if history is None:
            return

        self.__logger.debug(f"{my_colors.ERROR}{history=}{my_colors.END}")
        old_seq = history[-1][4]
        old_ack = history[-1][5]
        id_ = history[-1][0]
        # if len history==1 -> only initial packet from us is logged
        # in this case seq=ack because no ack exists
        # check only if the ack is old_seq+1
        # skip this check if we got FA packet, we dont care about seq/ack there
        if data[3]!="FA":
            if len(history)==1:
                if data[5] != old_seq+1:
                    self.__logger.debug(f"{my_colors.ERROR}[*] Skipping Packet.\n[*] New Ack does not fit initial seq_num.\n->{data[5]=}\n->{old_seq+1}{my_colors.END}")
                    return
            # otherwise, check seq and ack num
            # check if recieved ack is old_seq+1, else drop packet (may be a retransmission of a packet in the past)
            else:
                if data[4]!=old_seq+1:
                    self.__logger.debug(f"{my_colors.ERROR}[*] Skipping Packet. Ack and Seq do not fit.\n[*] New Ack->{data[5]=}\n[*] Old Ack->{old_ack}\n[*] New Seq->{data[4]}\n[*] Old Seq->{old_seq}{my_colors.END}")
                    # skip this packet
                    return
        if data[3] == "SA" and not data[6]:
            history.append((id_,data[0],data[1],data[2],data[4],data[5],data[3],""))
            self.__scan_data[(data[2],syn_num)] = history
            self.__logger.debug(f"{my_colors.SEND}[*] Sending Ack with DNS to:\n->ip={history[0][2]}\n->port={data[2]}\n->seq={data[5]}\n->ack={data[4]+1}{my_colors.END}")
            self.send_ack_with_dns(history[0][2],data[2],data[4],data[5]) #target ip, src port, seq num, ack num
        elif data[3] == "FA" or data[3] == "F":
            # put in write back queue
            self.__writeback.put((data[2],syn_num))
            # send ack to the fin request to close the connection properly
            self.__logger.debug(f"{my_colors.SEND}[*] Sending Ack for FA packet:\n->ip={data[1]}\n->port={data[2]}\n->seq={data[5]}\n->ack={data[4]+1}{my_colors.END}")
            self.send_ack_or_fin_packet(data[1],data[2],data[4],data[5],"A")
        elif data[3] == "R":
            self.__logger.debug(f"{my_colors.RECV}[*] Recieved R packet:\n->ip={data[1]}{my_colors.END}")
        elif data[6]:
            arecords_raw = data[6][0]
            if arecords_raw != "No RR Records in DNS answer":
                arecords = [arecords_raw[i].rdata for i in range(data[6][1])]
            else:
                arecords = [arecords_raw,"DNS Answer Count: "+str(data[6][1])]
            history.append((id_,data[0],data[1],data[2],data[4],data[5],data[3],arecords))
            self.__scan_data[(data[2],syn_num)] = history
            self.__logger.debug(f"{my_colors.SEND}[*] Sending Fin to:\n->ip={data[1]}\n->port={data[2]}\n->seq={data[5]}\n->ack={data[4]+1}{my_colors.END}")
            # send fin request to end transmission and ack dns answer
            self.send_ack_or_fin_packet(data[1],data[2],data[4],data[5],"FA")
        else:
            self.__logger.debug("{my_colors.ERROR}[*] Packet did not fit: {data=}{my_colors.END}")
            # return if packet does not fit into our scheme
            return

    def writeback_thread(self):
        while not self.__all_pkts_sent:
            # process all finished connections
            self.writeback_data(self.__writeback.get())
        self.__logger.info(f"{my_colors.INFO}[*] Writeback Thread is about to end...emptying queue.{my_colors.END}")
        while not self.__writeback.empty():
            self.writeback_data(self.__writeback.get())
        self.__logger.info(f"{my_colors.INFO}[*] Writeback thread is done.{my_colors.END}")
        return

    def writeback_data(self,scankey):
        with open(self.__config["log_file"],"a") as log_f:
            pkt_history = self.__scan_data[scankey]
            # just write the data from left to right
            data_line = ""
            self.__logger.debug(f"{my_colors.ERROR}{pkt_history=}{my_colors.END}")
            # skip if it is empty (already wrote it back but it was multiple times in writeback queue)
            if pkt_history:
                for pkt in pkt_history:
                    for data in pkt:
                        if type(data)==list:
                            for record in data:
                                data_line+=str(record)+","
                            # remove comma at the end
                            data_line = data_line[:-1]
                            data_line+=";"
                        else:
                            data_line+=str(data)+";"
                    # remove semicolon at the end
                    data_line = data_line[:-1]
                    log_f.write(data_line+"\n")
                    data_line = ""
        # empty data history
        self.__scan_data[scankey] = None

    def timeout(self):
        # go through current data log and look for missed writebacks
        for scankey in self.__scan_data.keys():
            data = self.__scan_data[scankey]
            if data:
                self.__logger.debug(f"{my_colors.ERROR}[*] Timeout on {scankey=}.{my_colors.END}")
                self.__writeback.put(scankey)

    def send_ack_or_fin_packet(self, target_ip, src_port, seq_num, ack_num, flags, payload_length = 1):
        ip = IP(src=self.__config["ip_client"], dst=target_ip, ttl=int(self.__config["ttl"]))
        ack = ip/TCP(sport=src_port,dport=int(self.__config["dst_port"]),flags=flags,seq=ack_num,ack = seq_num+payload_length)
        self.__s3.send(ack)

    def send_syn_packet(self, target_ip, src_port, seq_num):
        ip = self.__ip_pkt
        ip.dst = target_ip
        tcp = self.__tcp_syn_pkt
        tcp.sport = src_port
        tcp.seq = seq_num
        syn = self.__ether.copy()
        ip_clone = ip.copy()
        ip_clone.add_payload(tcp.copy())
        syn.add_payload(ip_clone)
        self.__s2.send(syn)

    def send_ack_with_dns(self, target_ip, src_port, seq_num, ack_num):
        ip = IP(src=self.__config["ip_client"], dst=target_ip, ttl=int(self.__config["ttl"]))
        request = DNS(rd=1, id=RandShort(), qd=DNSQR(qname=self.__config["qry_name"]))
        dnsreq = ip/TCP(sport=src_port,dport=int(self.__config["dst_port"]),flags="PA",seq=ack_num,ack = seq_num+1)/request
        self.__s3.send(dnsreq)

    def sniffer(self):
        sniff(iface=self.__config["iface"],filter=self.__bpf,store=False,
               prn = self.capture_packets, stop_filter = lambda _: self.__all_pkts_sent)

    def stop_threads(self):
        # end all running threads
        for thread in self.__running_threads:
            thread.join()
        self.timeout()


if __name__ == "__main__":
    # configure ip tables to stop network stack to automatically send RST packets
    os.system("sudo iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP > /dev/null 2>&1 || sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

    if len(argv) == 1:
        logging.info("missing file path or network in CIDR notation")
        exit(1)

    if len(argv) > 2:
        process_id = argv[2]
    else:
        process_id = 0
    measurement = DNS_Over_TCP(debug=False, process_id=int(process_id))
    pos_cidr_ip = argv[1].split('/')
    if '/' in argv[1] and len(pos_cidr_ip) == 2 and valid_ip(pos_cidr_ip[0]):
        logging.info("running in cidr mode")
        measurement.set_cidr_ip(pos_cidr_ip[0], 32-int(pos_cidr_ip[1]))
    else:
        logging.info("running in file mode")
        ip_addr_file = argv[1]
        measurement.set_ip_list(ip_addr_file)
    measurement.start_scanning()
    # delete ip tables rule
    # os.system("sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP")
