#! /usr/bin/env python3
###############################################################################
# import necessary scapy functions
from scapy.all import *

from scapy.layers.inet import IP,TCP
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
# threading module for multitasking
import threading
# add some colors for output
from colorama import Fore
from colorama import Style

# add process bar
from tqdm import tqdm
###############################################################################

class my_colors:
    END = Style.RESET_ALL
    SEND = Fore.GREEN
    RECV = Fore.YELLOW
    INFO = Fore.CYAN
    ERROR = Fore.RED

import hashlib

# Implementation of DNS Measurement
# should be separate from actual implementation
# of DNS (DNS over TCP, DNS over Http etc.)
# this may not be trivial so at first we only
# implement DNS over TCP
class DNS_Over_X:
    def __init__(self,debug):
        # turn debugging print statements on or off
        self.__debug = debug
        # list of ip addresses to scan
        self.__ip_list = []
        # stop condition for sniffer
        self.__all_pkts_sent = False
        # read config.ini file (DEFAULT section)
        self.__config = self.read_config(file = "config.ini",section="DEFAULT")
        # init bpf filter after loading config
        # sniff only on incoming pkts within portrange
        self.__bpf_filter = f"tcp and ip dst {self.__config['ip_client']} "
        self.__bpf_filter += f"and src port {self.__config['dst_port']} "
        self.__bpf_filter += f"and dst portrange {self.__config['portrange_min']}-{self.__config['portrange_max']}"
        #print(self.__bpf_filter)
        # list of free ports
        self.__freeports = [61000] #[i for i in range(int(self.__config['portrange_min']),int(self.__config['portrange_max']))]
        self.__port_sem = threading.Semaphore(value=len(self.__freeports))
        # temporary scan data (dictionary with port number as key
        # structure:
        # port:[ ( id, timestamp, IP-Adr., Dest. Port, TCP Seqnum, TCP Acknum, TCP Flags, DNS A Records ),... ]
        self.__scan_data = {}
        
        # init queues for answersg
        self.__pkt_queue = Queue()
        self.__writeback = Queue()

        self.__scan_thread = Thread(target = self.init_tcp_connections)
        self.__sniffer_thread = Thread(target = self.sniffer)
        self.__process_thread = Thread(target = self.process_responses_thread)
        self.__timeout_thread = Thread(target = self.timeout_thread)
        self.__writeback_thread = Thread(target = self.writeback_thread)
        # make sure to start sniffer thread first
        self.__running_threads = [self.__sniffer_thread, self.__scan_thread, 
                self.__process_thread, self.__timeout_thread,
                self.__writeback_thread]
        self.DNS_PAYLOAD_SIZE = len(DNS(rd=1, id=0, qd=DNSQR(qname=self.__config["qry_name"]))) +2

    def start_scanning(self):
        if self.__debug:
            print(f"{my_colors.INFO}[*] Starting Scan.{my_colors.END}")
        for thread in self.__running_threads:
            thread.start()

    def read_config(self,file,section):
        config = cp.ConfigParser()
        config.read(file)
        return config[section]

    def set_ip_list(self,fname):
        with open(fname) as ip_list:
            for line in ip_list.readlines():
                self.__ip_list.append(line[:-1])
        random.shuffle(self.__ip_list)
        if self.__debug:
            print(f"{my_colors.INFO}[*] Loading IP Adresses Done.")
            print(f"[*] Head: {self.__ip_list[:5]}{my_colors.END}")
    
    def get_free_port(self):
        # pick random free port
        #self.__port_sem.acquire()
        #port = random.choice(self.__freeports)
        # remove it from free port list
        #self.__freeports.remove(port)
        return 61000 #port

    def init_tcp_connections(self):
        # main thread which goes through all ip's in ip list
        # and sends syn packets
        for i in tqdm(range(len(self.__ip_list))):
            print("lets go: ",i)
            # if free port list is empty -> wait until a port is free again
            #while len(self.__freeports)==0:
                #print("waiting for port")
                #sleep(1)
            #    pass
            # free port(s) available
            port = self.get_free_port()
            # get random ip
            ip = self.get_next_ip()
            # get random (unused) seq_num
            seq = int.from_bytes(hashlib.sha256(ip.encode("utf-8")).digest()[:2], 'little') * 1000
            if self.__debug:
                print(f"{my_colors.SEND}[*] Sending SYN:\n-> {ip=}\n-> {port=}\n-> {seq=}{my_colors.END}")
                print(f"{my_colors.INFO}[*]{i=}{my_colors.END}")
            # add data to protocol, then send (to avoid delays when adding to protocol)
            # adding seq, seq to history is initially important -> it is seq and ack at the same time
            # to prevent failing to match the next packets as we compare seq with ack
            while (port,seq) in self.__scan_data:
                seq = (int.from_bytes(hashlib.sha256(ip.encode("utf-8")).digest()[:2], 'little')+42)* 1000
            self.__scan_data[(port,seq)] = [(i,datetime.utcnow(),ip,port,seq,seq,"S","")]
            # send syn packet to ip
            self.send_syn_packet(ip,port,seq)
            print("sending done.")
        #self.stop_threads()
        print(f"{my_colors.INFO}[*] Sending SYN Packets Done.{my_colors.END}")
        sleep(15)
        print(f"{my_colors.INFO}[*] Slowly Shutting Down Scan/Capture Process.{my_colors.END}")
        self.__all_pkts_sent = True
        self.__running_threads.remove(self.__scan_thread)
        self.stop_threads()
        return

    def capture_packets(self,pkt):
        # got syn/ack?
        if self.__debug:
            print(f"{my_colors.RECV}[*] Captured Packet: {pkt.summary()}{my_colors.END}")
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
            if self.__debug:
                print(f"{my_colors.INFO}[*] Got data in queue: {data}{my_colors.END}")
            self.process_packet_data(data)
        print(f"{my_colors.INFO}[*] Processing responses is about to end...emptying queue.{my_colors.END}")
        # empty queue
        while not self.__pkt_queue.empty():
            self.process_packet_data(self.__pkt_queue.get())
        print(f"{my_colors.INFO}[*] Processing responses done.{my_colors.END}")
        # writeback queue stays blocked -> free it by filling it with a dummy port, all ports should be empty by now
        # so we can use whatever port we want
        self.__writeback.put(10000)
        return

    def process_packet_data(self,data):
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
        
        if self.__debug:
            print(f"{my_colors.ERROR}{history=}{my_colors.END}")
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
                    if self.__debug:
                        print(f"{my_colors.ERROR}[*] Skipping Packet.\n[*] New Ack does not fit initial seq_num.\n->{data[5]=}\n->{old_seq+1}{my_colors.END}")
                    return
            # otherwise, check seq and ack num
            # check if recieved ack is old_seq+1, else drop packet (may be a retransmission of a packet in the past)
            else:
            #    if data[4]!=old_seq+1 or data[5]!=old_ack+1:
                # for some reason, only seq nums fit (why!?!)
                if data[4]!=old_seq+1:
                    if self.__debug:
                        print(f"{my_colors.ERROR}[*] Skipping Packet. Ack and Seq do not fit.\n[*] New Ack->{data[5]=}\n[*] Old Ack->{old_ack}\n[*] New Seq->{data[4]}\n[*] Old Seq->{old_seq}{my_colors.END}")
                    # skip this packet
                    return
        # definition of data:
        # list with format
        # Index: 0             1               2           3          4           5                       6
        # [ timestamp, Source IP-Address, Dest. Port, TCP Flags, TCP Seqnum, TCP Acknum, (DNS Res. Records, DNS Answer Count) ]
        if data[3] == "SA" and not data[6]:
            history.append((id_,data[0],data[1],data[2],data[4],data[5],data[3],""))
            self.__scan_data[(data[2],syn_num)] = history
            if self.__debug:
                print(f"{my_colors.SEND}[*] Sending Ack with DNS to:\n->ip={history[0][2]}\n->port={data[2]}\n->seq={data[5]}\n->ack={data[4]+1}{my_colors.END}")
            self.send_ack_with_dns(history[0][2],data[2],data[4],data[5]) #target ip, src port, seq num, ack num
        elif data[3] == "FA" or data[3] == "F":
            # put in write back queue
            self.__writeback.put((data[2],syn_num))
            # send ack to the fin request to close the connection properly
            if self.__debug:
                print(f"{my_colors.SEND}[*] Sending Ack for FA packet:\n->ip={data[1]}\n->port={data[2]}\n->seq={data[5]}\n->ack={data[4]+1}{my_colors.END}")
            self.send_ack_or_fin_packet(data[1],data[2],data[4],data[5],"A")
        elif data[3] == "R":
                print(f"{my_colors.RECV}[*] Recieved R packet:\n->ip={data[1]}{my_colors.END}")
        elif data[6]:
            arecords_raw = data[6][0]
            if arecords_raw != "No RR Records in DNS answer":
                arecords = [arecords_raw[i].rdata for i in range(data[6][1])]
            else:
                arecords = [arecords_raw,"DNS Answer Count: "+str(data[6][1])]
            history.append((id_,data[0],data[1],data[2],data[4],data[5],data[3],arecords))
            self.__scan_data[(data[2],syn_num)] = history
            if self.__debug:
                print(f"{my_colors.SEND}[*] Sending Fin to:\n->ip={data[1]}\n->port={data[2]}\n->seq={data[5]}\n->ack={data[4]+1}{my_colors.END}")
            # send fin request to end transmission and ack dns answer
            self.send_ack_or_fin_packet(data[1],data[2],data[4],data[5],"FA")
        else:
            if self.__debug:
                print("{my_colors.ERROR}[*] Packet did not fit: {data=}{my_colors.END}")
            # return if packet does not fit into our scheme
            return

    def writeback_thread(self):
        while not self.__all_pkts_sent:
            # process all finished connections
            self.writeback_data(self.__writeback.get())
        print(f"{my_colors.INFO}[*] Writeback Thread is about to end...emptying queue.{my_colors.END}")
        while not self.__writeback.empty():
            self.writeback_data(self.__writeback.get())
        print(f"{my_colors.INFO}[*] Writeback thread is done.{my_colors.END}")
        return

    def writeback_data(self,scankey):
        #print(f"[*] Port: {port}")
        with open(self.__config["log_file"],"a") as log:
            pkt_history = self.__scan_data[scankey]
            # just write the data from left to right
            data_line = ""
            if self.__debug:
                print(f"{my_colors.ERROR}{pkt_history=}{my_colors.END}")
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
                    log.write(data_line+"\n")
                    data_line = ""
        # empty data history
        self.__scan_data[scankey] = None

    def timeout_thread(self):
        while not self.__all_pkts_sent:
            # go through current data log and watch for missing answers
            # detected bydifference of last arrived packet till now
            for scankey in self.__scan_data.keys():
                timestamp = datetime.utcnow()
                data = self.__scan_data[scankey]
                if data:
                    #if self.__debug:
                    #    print(f"[*] Current Scan Data:\n->{port=}\n->{data=}")
                    # data[-1][0] contains most recent timestamp
                    timedelta = timestamp - data[-1][1]
                    # timeout after 10 seconds (arbitrary!)
                    if timedelta.total_seconds() > 10:
                        if self.__debug:
                            print(f"{my_colors.ERROR}[*] Timeout on {scankey=}.{my_colors.END}")
                        self.__writeback.put(scankey)
        print(f"{my_colors.INFO}[*] Timeout Thread is done.{my_colors.END}")
        return

    def send_ack_or_fin_packet(self, target_ip, src_port, seq_num, ack_num, flags, payload_length = 1):
        ip = IP(src=self.__config["ip_client"], dst=target_ip, ttl=int(self.__config["ttl"]))
        ack = ip/TCP(sport=src_port,dport=int(self.__config["dst_port"]),flags=flags,seq=ack_num,ack = seq_num+payload_length)
        send(ack,verbose = False)

    def send_syn_packet(self,target_ip, src_port, seq_num):
        # build TCP/IP Packet and send it to target
        ip = IP(src=self.__config["ip_client"], dst=target_ip, ttl=int(self.__config["ttl"]))
        syn = ip/TCP(sport=src_port, dport=int(self.__config["dst_port"]), flags="S",seq=seq_num)
        print("built packet")
        send(syn, verbose = True)
        print("sending is done!")

    def send_ack_with_dns(self, target_ip, src_port, seq_num, ack_num):
        ip = IP(src=self.__config["ip_client"], dst=target_ip, ttl=int(self.__config["ttl"]))
        request = DNS(rd=1, id=RandShort(), qd=DNSQR(qname=self.__config["qry_name"]))
        dnsreq = ip/TCP(sport=src_port,dport=int(self.__config["dst_port"]),flags="PA",seq=ack_num,ack = seq_num+1)/request
        send(dnsreq, verbose = False)

    def get_next_ip(self):
        # pick random ip
        ip = random.choice(self.__ip_list)
        # remove it from the list
        self.__ip_list.remove(ip)
        # return next ip
        return ip

    def sniffer(self):
       sniff(iface=self.__config["iface"],filter=self.__bpf_filter,store=False,
               prn = self.capture_packets, stop_filter = lambda _: self.__all_pkts_sent)

    def stop_threads(self):
        # end all running threads
        for thread in self.__running_threads:
            thread.join()


if __name__ == "__main__":
    # configure ip tables to stop network stack to automatically send RST packets
    os.system("sudo iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP > /dev/null || sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

    measurement = DNS_Over_X(True)
    ip_addr_file = argv[1]
    measurement.set_ip_list(ip_addr_file)
    measurement.start_scanning()
    # delete ip tables rule
    # os.system("sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP")
