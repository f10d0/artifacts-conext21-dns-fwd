from postprocessing_data_functions import *

load_fname = "tcp_results_2024-01-08_test.csv.gz"
save_fname = "tcp_results_combined.csv.gz"

colnames = ["id", "ts", "ip", "port", "seqnum", "acknum", "tcpflags", "arecords"]
loaded_df = pd.read_csv(load_fname, sep=";", names=colnames)
print(loaded_df.head(n=10))


def process_data(df):
    output = []

    for id_value, group in df.groupby('id'):
        # the ip field in the SYN row is the targeted ip
        targetip = group[group['tcpflags'] == 'S']['ip'].iloc[0]
        responseip = targetip

        # check for different ip in SYN-ACK or PSH-ACK rows
        for tcpflag in ['SA', 'PA', 'FPA']:
            tmpdf = group[group['tcpflags'] == tcpflag]
            if tmpdf.empty: continue
            ip = tmpdf['ip'].iloc[0]
            if ip != targetip:
                responseip = ip
                break
        
        # processing arecords
        arecords = group['arecords'].dropna().tolist()
        arecord = ''
        for record in arecords:
            ips = record.split(',')
            if '91.216.216.216' in ips:
                ips.remove('91.216.216.216')
                arecord = ips[0] if ips else ''
                break

        output.append({'id': id_value, 'targetip': targetip, 'responseip': responseip, 'arecord': arecord})

    return pd.DataFrame(output)

processed_df = process_data(loaded_df)
print(process_data.head(n=40))
processed_df.to_csv(save_fname, sep='\n')