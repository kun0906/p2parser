import os
import numpy as np
from collections import OrderedDict

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP


def session_extractor(p):
    """Extract sessions from packets"""
    if 'Ether' in p:
        if 'IP' in p or 'IPv6' in p:
            ip_src_fmt = "{IP:%IP.src%}{IPv6:%IPv6.src%}"
            ip_dst_fmt = "{IP:%IP.dst%}{IPv6:%IPv6.dst%}"
            addr_fmt = (ip_src_fmt, ip_dst_fmt)
            if 'TCP' in p:
                fmt = "TCP {}:%r,TCP.sport% > {}:%r,TCP.dport%"
            elif 'UDP' in p:
                fmt = "UDP {}:%r,UDP.sport% > {}:%r,UDP.dport%"
            # elif 'ICMP' in p:
            #     fmt = "ICMP {} > {} type=%r,ICMP.type% code=%r," \
            #           "ICMP.code% id=%ICMP.id%"
            # elif 'ICMPv6' in p:
            #     fmt = "ICMPv6 {} > {} type=%r,ICMPv6.type% " \
            #           "code=%r,ICMPv6.code%"
            # elif 'IPv6' in p:
            #     fmt = "IPv6 {} > {} nh=%IPv6.nh%"
            else:
                fmt = "IP {} > {} proto=%IP.proto%"
            return p.sprintf(fmt.format(*addr_fmt))
        # elif 'ARP' in p:
        #     return p.sprintf("ARP %ARP.psrc% > %ARP.pdst%")
        # else:
        #     return p.sprintf("Ethernet type=%04xr,Ether.type%")
    return "Other"


def pcap2sessions(pcap_file):
    sessions = OrderedDict()
    "filter pcap_file only contains the special srcIP "
    try:
        # sessions= rdpcap(pcap_file).sessions()
        # res = PcapReader(pcap_file).read_all(count=-1)
        # from scapy import plist
        # sessions = plist.PacketList(res, name=os.path.basename(pcap_file)).sessions()
        for i, pkt in enumerate(PcapReader(pcap_file)):  # iteratively get packet from the pcap
            if i % 10000 == 0:
                print(f'i_pkt: {i}')
            sess_key = session_extractor(pkt)
            if 'TCP' in sess_key or 'UDP' in sess_key:
                if sess_key not in sessions.keys():
                    sessions[sess_key] = [pkt]
                else:
                    sessions[sess_key].append(pkt)
    except Exception as e:
        print('Error', e)

    def get_frame_time(pkt):
        return float(pkt.time)

    new_sessions = copy.deepcopy(sessions)
    num_pkts_thres=2
    for i, (key, sess) in enumerate(sessions.items()):
        if len(sess) >= max(2, num_pkts_thres):
            new_sessions[key] = sorted(sess, key=get_frame_time, reverse=False)
        else:
            del new_sessions[key]
        # sessions[key] = sorted(sess, key=lambda pkt: float(pkt.time), reverse=False)


    return new_sessions


def sessions2flows(sessions, interval=-1):
    flows = []

    if interval <= 0:  # get flows
        for i, (key, sess) in enumerate(sessions.items()):
            flow_i = []
            for j, pkt in enumerate(sess):
                if IP in pkt and TCP in pkt:
                    flow_type = 'TCP'
                    fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 6)
                    flow_i.append((float(pkt.time), len(pkt)))
                elif IP in pkt and UDP in pkt:
                    flow_type = 'UDP'
                    fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 17)
                    flow_i.append((float(pkt.time), len(pkt)))
                else:
                    pass
            if flow_type in ['TCP', 'UDP']:
                flows.append((fid, flow_i))

        num_pkt_thresh = 2
        # sort all flows by packet arrival time, each flow must have at least two packets
        flows = [(fid, *list(zip(*sorted(times_pkts)))) for fid, times_pkts in flows if
                 len(times_pkts) >= max(2, num_pkt_thresh)]
        print(f'len(flows): {len(flows)},')

        return flows

    else:
        remainder_cnt = 0
        new_cnt = 0         # a flow is not split by an interval
        print(len(sessions.keys()))
        for i, (key, sess) in enumerate(sessions.items()):
            # print(f'session_i: {i}')
            flow_i = []
            flow_type = None
            subflow = []
            new_flow = 0
            for j, pkt in enumerate(sess):
                if TCP not in pkt and UDP not in pkt:
                    break
                if j == 0:
                    flow_start_time = float(pkt.time)
                    subflow = [(float(pkt.time), len(pkt))]
                    split_flow = False      # if a flow is not split with interval, label it as False, otherwise, True
                    continue
                # handle TCP packets
                if IP in pkt and TCP in pkt:
                    flow_type = 'TCP'
                    fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 6)
                    if float(pkt.time) - flow_start_time > interval:
                        flow_i.append((fid, subflow))
                        flow_start_time += int((float(pkt.time) - flow_start_time) // interval) * interval
                        subflow = [(float(pkt.time), len(pkt))]
                        split_flow=True
                    else:
                        subflow.append((float(pkt.time), len(pkt)))

                # handle UDP packets
                elif IP in pkt and UDP in pkt:
                    # parse 5-tuple flow ID
                    fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 17)
                    flow_type = 'UDP'
                    if float(pkt.time) - flow_start_time > interval:
                        flow_i.append((fid, subflow))
                        flow_start_time += int((float(pkt.time) - flow_start_time) // interval) * interval
                        subflow = [(float(pkt.time), len(pkt))]
                        split_flow=True
                    else:
                        subflow.append((float(pkt.time), len(pkt)))

            if (split_flow == False) and (flow_type in ['TCP', 'UDP']):
                new_cnt +=1
                flow_i.append((fid, subflow))
            else:
                remainder_cnt +=1
                # flow_i.append((fid, subflow)) # don't include the remainder
                # print(i, new_flow, subflow)

            flows.extend(flow_i)

        print(f'all subflows: {len(flows)}, new_flows: {new_cnt}, old_flows: {remainder_cnt}')

    num_pkt_thresh = 2
    # sort all flows by packet arrival time, each flow must have at least two packets
    flows = [(fid, *list(zip(*sorted(times_pkts)))) for fid, times_pkts in flows if
             len(times_pkts) >= max(2, num_pkt_thresh)]
    print(f'len(flows): {len(flows)},')

    return flows


def get_flows_durations(flows):
    return [times[-1] - times[0] for fid, times, sizes in flows]


if __name__ == '__main__':
    # pcap_file = './dataset/srcIP_10.42.0.1_normal.pcap'
    # out_dir = 'output'
    #
    # sessions = pcap2sessions(pcap_file)
    # flows = sessions2flows(sessions)
    # print(len(flows))
    # flows_durations = get_flows_durations(flows)
    # intervals = np.quantile(flows_durations, q=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95])
    # print(intervals)
    # flows = sessions2flows(sessions, interval=1.01118281)
    # print(len(flows))

    pcap_file ='./dataset/srcIP_10.42.0.119_anomaly.pcap'
    sessions = pcap2sessions(pcap_file)
    # flows = sessions2flows(sessions)
    flows = sessions2flows(sessions, interval=1.0093828439712524)
    print(len(flows))

