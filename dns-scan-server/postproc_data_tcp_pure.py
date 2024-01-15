from dataclasses import dataclass
from ipaddress import ip_address
from enum import Enum
import gzip
import sys

# this will more or less represent a single row of the output csv
@dataclass
class OutputItem:
    target_ip: ip_address
    response_ip: ip_address
    arecord: ip_address # if the control ip is not present the entire item is removed from output frame
    timestamp: str
    integrity: bytes # 0 0 0 0 0 SYN SYN-ACK (FIN)-PSH-ACK ==> must be 7 in the end

class InPos(Enum):
    ID = 0
    TS = 1
    IP = 2
    FLAGS = 6
    RECS = 7

# input csv id is key
output_df: dict[int, OutputItem]= {}

if len(sys.argv) == 2:
    load_fname = sys.argv[1]
    save_fname = sys.argv[1].split(".")[0]+"_combined.csv.gz"
else:
    print("call like this: python postproc_data_tcp_pure.py <filename.csv.gz>")
    exit(1)

# we will read the input csv
# as soon as we learn some new information from a line, the output "dataframe" will be updated
# we will disregard any information not needed (like the timestamp, port, & seqnums)
# the response ip will be determined by the srcip of the PSH-ACK, this will be correct for both types of forwarders
# we will only check if a SYN-ACK is in principle present in the input csv
with gzip.open(load_fname, 'rt', encoding="utf-8") as input_file:
    while line := input_file.readline():
        # id,timestamp,ip,port,seqnum,acknum,flags,arecords -> Enum
        # 0 |    1    |2 | 3  |  4   | 5    | 6   | 7
        split = line.strip().split(";")
        if split[InPos.ID.value] in output_df:
            outitem = output_df[split[InPos.ID.value]]
        else:
            outitem = OutputItem(None, None, None, "", 0)
            output_df[split[InPos.ID.value]] = outitem

        # we shall have a SYN
        if split[InPos.FLAGS.value] == "S":
            outitem.target_ip = ip_address(split[InPos.IP.value])
            outitem.timestamp = split[InPos.TS.value]
            outitem.integrity = outitem.integrity | 0x4
        elif split[InPos.FLAGS.value] == "SA":
            outitem.integrity = outitem.integrity | 0x2
        elif split[InPos.FLAGS.value] == "PA" or split[InPos.FLAGS.value] == "FPA":
            outitem.response_ip = ip_address(split[InPos.IP.value])
            arecs = split[InPos.RECS.value].split(",")
            # there should be two entries, one of them the control ip
            if len(arecs) != 2:
                output_df.pop(InPos.ID.value, None) # remove from output dict
                continue
            try:
                pos = arecs.index("91.216.216.216")
            except ValueError:
                output_df.pop(InPos.ID.value, None) # remove from output dict
                continue
            outitem.arecord = ip_address(arecs[1-pos])

            outitem.integrity = outitem.integrity | 0x1

# writeout
with gzip.open(save_fname, "wt", encoding="utf-8") as out_file:
    for id, item in output_df.items():
        if item.integrity == 0x7:
            out_file.write(f"{id};{item.target_ip};{item.response_ip};{item.arecord};{item.timestamp}\n")
        #else: print(f"integrity failing for {id},{item}")