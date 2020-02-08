import os
import numpy as np
from collections import OrderedDict, Counter

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP



def session_extractor(pkt):
    """Extract sessions from packets"""
    if IP in pkt and TCP in pkt:
        flow_type = 'TCP'
        fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 6)
        return fid
    elif IP in pkt and UDP in pkt:
        flow_type = 'UDP'
        fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 17)
        return fid

    return 'other'
#
#
# def pcap2sessions(pcap_file):
#     sessions = OrderedDict()
#     num_pkts=0
#     "filter pcap_file only contains the special srcIP "
#     try:
#         # sessions= rdpcap(pcap_file).sessions()
#         # res = PcapReader(pcap_file).read_all(count=-1)
#         # from scapy import plist
#         # sessions = plist.PacketList(res, name=os.path.basename(pcap_file)).sessions()
#         for i, pkt in enumerate(PcapReader(pcap_file)):  # iteratively get packet from the pcap
#             if i % 10000 == 0:
#                 print(f'i_pkt: {i}')
#             sess_key = session_extractor(pkt)
#             if ('TCP' in sess_key) or ('UDP' in sess_key) or (6 in sess_key) or (17 in sess_key):
#                 if sess_key not in sessions.keys():
#                     sessions[sess_key] = [pkt]
#                 else:
#                     sessions[sess_key].append(pkt)
#         num_pkts = i + 1
#     except Exception as e:
#         print('Error', e)
#
#     def get_frame_time(pkt):
#         return float(pkt.time)
#
#     new_sessions = copy.deepcopy(sessions)
#     num_pkts_thres=2
#     for i, (key, sess) in enumerate(sessions.items()):
#         if len(sess) >= max(2, num_pkts_thres):
#             new_sessions[key] = sorted(sess, key=get_frame_time, reverse=False)
#         else:
#             del new_sessions[key]
#         # sessions[key] = sorted(sess, key=lambda pkt: float(pkt.time), reverse=False)
#
#     return flows, num_pkts

#
# def sessions2flows(sessions, interval=-1, num_pkt_thresh=2):
#     flows = []
#
#     if interval <= 0:  # get flows
#         pass
#
#     else:
#         remainder_cnt = 0
#         new_cnt = 0         # a flow is not split by an interval
#         print(len(sessions.keys()))
#         for i, (key, sess) in enumerate(sessions.items()):
#             # print(f'session_i: {i}')
#             flow_i = []
#             flow_type = None
#             subflow = []
#             new_flow = 0
#             for j, pkt in enumerate(sess):
#                 if TCP not in pkt and UDP not in pkt:
#                     break
#                 if j == 0:
#                     flow_start_time = float(pkt.time)
#                     subflow = [(float(pkt.time), pkt)]
#                     split_flow = False      # if a flow is not split with interval, label it as False, otherwise, True
#                     continue
#                 # handle TCP packets
#                 if IP in pkt and TCP in pkt:
#                     flow_type = 'TCP'
#                     fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 6)
#                     if float(pkt.time) - flow_start_time > interval:
#                         flow_i.append((fid, subflow))
#                         flow_start_time += int((float(pkt.time) - flow_start_time) // interval) * interval
#                         subflow = [(float(pkt.time), pkt)]
#                         split_flow=True
#                     else:
#                         subflow.append((float(pkt.time), pkt))
#
#                 # handle UDP packets
#                 elif IP in pkt and UDP in pkt:
#                     # parse 5-tuple flow ID
#                     fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 17)
#                     flow_type = 'UDP'
#                     if float(pkt.time) - flow_start_time > interval:
#                         flow_i.append((fid, subflow))
#                         flow_start_time += int((float(pkt.time) - flow_start_time) // interval) * interval
#                         subflow = [(float(pkt.time), pkt)]
#                         split_flow=True
#                     else:
#                         subflow.append((float(pkt.time), pkt))
#
#             if (split_flow == False) and (flow_type in ['TCP', 'UDP']):
#                 new_cnt +=1
#                 flow_i.append((fid, subflow))
#             else:
#                 remainder_cnt +=1
#                 # flow_i.append((fid, subflow)) # don't include the remainder
#                 # print(i, new_flow, subflow)
#
#             flows.extend(flow_i)
#
#         print(f'all subflows: {len(flows)}, new_flows: {new_cnt}, old_flows: {remainder_cnt}')
#
#         # sort all flows by packet arrival time, each flow must have at least two packets
#         flows = [(fid, *list(zip(*sorted(times_pkts)))) for fid, times_pkts in flows if
#                  len(times_pkts) >= max(2, num_pkt_thresh)]
#         print(f'len(flows): {len(flows)},')
#
#         return flows
#



def _load_pcap_to_flows(pcap_file, num_pkt_thresh=2, max_flows=25000, verbose=True):
    '''Reads pcap and divides packets into 5-tuple flows (arrival times and sizes)

       Arguments:
         pcap_file (string) = path to pcap file
         num_pkt_thresh (int) = discards flows with fewer packets than max(2, thresh)

       Returns:
         flows (list) = [(fid, arrival times list, packet sizes list)]
    '''

    sessions = OrderedDict()
    num_pkts = 0
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
            # if ('TCP' in sess_key) or ('UDP' in sess_key) or (6 in sess_key) or (17 in sess_key):
            if (TCP in pkt) or (UDP in pkt):
                if sess_key not in sessions.keys():
                    sessions[sess_key] = [pkt]
                else:
                    sessions[sess_key].append(pkt)
        num_pkts = i + 1
    except Exception as e:
        print('Error', e)

    def get_frame_time(pkt):
        return float(pkt.time)

    # in order to reduce the size of sessions and sort the pkt by time for the latter part.
    new_sessions = copy.deepcopy(sessions)
    for i, (key, sess) in enumerate(sessions.items()):
        if len(sess) >= max(2, num_pkt_thresh):
            new_sessions[key] = sorted(sess, key=get_frame_time, reverse=False)     # here it will spend too much time, however, it is neccessary to do that.
        else:
            del new_sessions[key]
        # sessions[key] = sorted(sess, key=lambda pkt: float(pkt.time), reverse=False)

    flows = []  # store all the flows

    TCP_TIMEOUT = 600       # 600seconds, 10 mins
    UDP_TIMEOUT = 600       # 10mins.

    remainder_cnt = 0
    new_cnt = 0  # a flow is not split by an interval
    print('all flows that have flows more than timeout, ', len(new_sessions.keys()))
    num_pkts = 0
    for i, (key, sess) in enumerate(new_sessions.items()):
        num_pkts += len(sess)
        # print(f'session_i: {i}')
        flow_i = []
        flow_type = None
        subflow = []
        new_flow = 0
        for j, pkt in enumerate(sess):
            if TCP not in pkt and UDP not in pkt:
                break
            if j == 0:
                subflow = [(float(pkt.time), pkt)]
                split_flow = False  # if a flow is not split with interval, label it as False, otherwise, True
                continue
            # handle TCP packets
            if IP in pkt and TCP in pkt:
                flow_type = 'TCP'
                fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 6)
                if float(pkt.time) - subflow[-1][0] > TCP_TIMEOUT:      # timeout between the previous pkt and the current one.
                    flow_i.append((fid, subflow))
                    subflow = [(float(pkt.time), pkt)]
                    split_flow = True
                else:
                    subflow.append((float(pkt.time), pkt))

            # handle UDP packets
            elif IP in pkt and UDP in pkt:
                # parse 5-tuple flow ID
                fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 17)
                flow_type = 'UDP'
                if float(pkt.time) - subflow[-1][0] > UDP_TIMEOUT:
                    flow_i.append((fid, subflow))
                    subflow = [(float(pkt.time), pkt)]
                    split_flow = True
                else:
                    subflow.append((float(pkt.time), pkt))

        if (flow_type in ['TCP', 'UDP']):
            flow_i.append((fid, subflow))

        flows.extend(flow_i)

    print(f'all subflows: {len(flows)}')
    # sort all flows by packet arrival time, each flow must have at least two packets
    flows = [(fid, *list(zip(*sorted(times_pkts)))) for fid, times_pkts in flows if
             len(times_pkts) >= max(2, num_pkt_thresh)]
    print(f'len(flows): {len(flows)},')

    return flows, num_pkts



def _load_pcap_to_subflows(pcap_file, num_pkt_thresh=2, interval=0.01, max_pkts=50000, max_flows=20000, verbose=True):
    '''Reads pcap and divides packets into 5-tuple flows (arrival times and sizes)

       Arguments:
         pcap_file (string) = path to pcap file
         num_pkt_thresh (int) = discards flows with fewer packets than max(2, thresh)

       Returns:
         flows (list) = [(fid, arrival times list, packet sizes list)]
    '''

    full_flows, num_pkts = _load_pcap_to_flows(pcap_file, num_pkt_thresh=2, max_flows=25000, verbose=True)
    remainder_cnt = 0
    new_cnt = 0  # a flow is not split by an intervals
    flows=[]        # store the subflows
    for i, (fid, times, pkts) in enumerate(full_flows):
        # print(f'session_i: {i}')
        flow_i = []
        flow_type = None
        subflow = []
        new_flow = 0
        for j, pkt in enumerate(pkts):
            if TCP not in pkt and UDP not in pkt:
                break
            if j == 0:
                flow_start_time = float(pkt.time)
                subflow = [(float(pkt.time), pkt)]
                split_flow = False  # if a flow is not split with interval, label it as False, otherwise, True
                continue
            # handle TCP packets
            if IP in pkt and TCP in pkt:
                flow_type = 'TCP'
                fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 6)
                if float(pkt.time) - flow_start_time > interval:
                    flow_i.append((fid, subflow))
                    flow_start_time += int((float(pkt.time) - flow_start_time) // interval) * interval
                    subflow = [(float(pkt.time), pkt)]
                    split_flow = True
                else:
                    subflow.append((float(pkt.time), pkt))

            # handle UDP packets
            elif IP in pkt and UDP in pkt:
                # parse 5-tuple flow ID
                fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 17)
                flow_type = 'UDP'
                if float(pkt.time) - flow_start_time > interval:
                    flow_i.append((fid, subflow))
                    flow_start_time += int((float(pkt.time) - flow_start_time) // interval) * interval
                    subflow = [(float(pkt.time), pkt)]
                    split_flow = True
                else:
                    subflow.append((float(pkt.time), pkt))

        if (split_flow == False) and (flow_type in ['TCP', 'UDP']):
            new_cnt += 1
            flow_i.append((fid, subflow))
        else:
            remainder_cnt += 1
            # flow_i.append((fid, subflow)) # don't include the remainder
            # print(i, new_flow, subflow)

        flows.extend(flow_i)

    print(f'all subflows: {len(flows)}, new_flows: {new_cnt}, old_flows: {remainder_cnt}')

    # sort all flows by packet arrival time, each flow must have at least two packets
    flows = [(fid, *list(zip(*sorted(times_pkts)))) for fid, times_pkts in flows if
             len(times_pkts) >= max(2, num_pkt_thresh)]
    print(f'len(flows): {len(flows)},')

    return flows


def get_flows_durations(flows):
    return [times[-1] - times[0] for fid, times, sizes in flows]


if __name__ == '__main__':
    pcap_file = './dataset/srcIP_10.42.0.1_normal.pcap'
    # pcap_file ='./dataset/srcIP_192.168.10.5_AGMT.pcap'
    # pcap_file ='./dataset/bose_soundtouch-2daysactiv-src_192.168.143.48-anomaly.pcap'
    # # pcap_file='./dataset/bose_soundtouch-2daysactiv-src_192.168.143.48-normal.pcap'
    out_dir = 'output'

    flows, num_pkts = _load_pcap_to_flows(pcap_file)
    print(len(flows))
    flows_durations = get_flows_durations(flows)
    intervals = np.quantile(flows_durations, q=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95])
    print(intervals)
    interval = np.quantile(flows_durations, q=0.9)
    flows = _load_pcap_to_subflows(pcap_file, interval=interval)
    print(len(flows))

    # pcap_file ='./dataset/srcIP_10.42.0.119_anomaly.pcap'
    # # flows, num_pkts = _load_pcap_to_flows(pcap_file)
    # flows = _load_pcap_to_subflows(pcap_file, interval=1.01118281)
    # print(len(flows))

