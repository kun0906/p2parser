import os
import numpy as np
from collections import OrderedDict, Counter

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP


def _load_pcap_to_flows(pcap_file, num_pkt_thresh=2, max_flows=25000, verbose=True):
    '''Reads pcap and divides packets into 5-tuple flows (arrival times and sizes)

       Arguments:
         pcap_file (string) = path to pcap file
         num_pkt_thresh (int) = discards flows with fewer packets than max(2, thresh)

       Returns:
         flows (list) = [(fid, arrival times list, packet sizes list)]
    '''

    TCP_TIMEOUT = 600  # 600 seconds
    UDP_TIMEOUT = 600  # 600 seconds

    # if verbose:
    #     funcparams_dict = {'pcap_file': pcap_file, 'TCP_TIMEOUT': TCP_TIMEOUT, 'UDP_TIMEOUT': UDP_TIMEOUT,
    #                        'num_pkt_thresh': num_pkt_thresh, 'verbose': verbose}
    #     pprint(OrderedDict(funcparams_dict), name=_load_pcap_to_flows.__name__)

    # read packets iteratively
    active_flows = defaultdict(list)
    all_flows = []
    pkts_tcp = 0
    pkts_udp = 0
    pkts_other = 0

    tcp_cnt = 0
    udp_cnt = 0

    for i, pkt in enumerate(PcapReader(pcap_file)):
        if i % 10000 == 0:
            print("Packet {}".format(i))

        # handle TCP packets
        if IP in pkt and TCP in pkt:
            pkts_tcp += 1
            # parse 5-tuple flow ID
            fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 6)
            # create a new active flow if one doesn't exist
            if not active_flows[fid]:
                active_flows[fid].append((float(pkt.time), pkt))
                continue
            # if this packet is a FIN, add it and close the active flow
            if pkt[TCP].flags.F:
                active_flows[fid].append((float(pkt.time), pkt))
                all_flows.append((fid, active_flows[fid]))
                del active_flows[fid]
            # if the TCP timeout has elapsed, close the old active flow and start anew
            elif float(pkt.time) - active_flows[fid][-1][0] > TCP_TIMEOUT:
                # print(f'+++a few change it will happen for TCP_TIMEOUT {TCP_TIMEOUT}, Because it requires the last packet of the flow {fid} arrivals, however, it usually won\'t happen when timeout happens.')
                all_flows.append((fid, active_flows[fid]))
                del active_flows[fid]
                active_flows[fid].append((float(pkt.time), pkt))
            # otherwise, add to existing flow
            else:
                active_flows[fid].append((float(pkt.time), pkt))

        # handle UDP packets
        elif IP in pkt and UDP in pkt:
            pkts_udp += 1
            # parse 5-tuple flow ID
            fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 17)
            # create a new active flow if one doesn't exist
            if not active_flows[fid]:
                active_flows[fid].append((float(pkt.time), pkt))
                continue
            # if UDP timeout has elapsed, close the old active flow and start anew
            if float(pkt.time) - active_flows[fid][-1][0] > UDP_TIMEOUT:  #
                # print(f'---a few change it will happen for UDP_TIMEOUT {UDP_TIMEOUT}, Because it requires the last packet of the flow {fid} arrivals, however, it usually won\'t happen when timeout happens.')
                all_flows.append((fid, active_flows[fid]))
                del active_flows[fid]
                active_flows[fid].append((float(pkt.time), pkt))
            # otherwise add to existing flow
            else:
                active_flows[fid].append((float(pkt.time), pkt))
        else:
            # print(i, pkt[IP].proto)
            pkts_other += 1

        # # handle timeout here again (it must be done for TIMEOUT for each active flow again).
        # keys = copy.deepcopy(list(active_flows.keys()))
        # for j, fid in enumerate(keys):
        #     # # if the TCP timeout has elapsed, close the old active flow and start anew
        #      # handle TCP packets
        #     if IP in pkt and TCP in pkt:
        #         if float(pkt.time) - active_flows[fid][-1][0] > TCP_TIMEOUT :
        #             tcp_cnt +=1
        #             if verbose and tcp_cnt % 10000 ==0:
        #                 print(f'+++ pkt:{i}, TCP_TIMEOUT {TCP_TIMEOUT} happens for a flow {fid}, float(pkt.time) - active_flows[fid][-1][0]: {float(pkt.time) - active_flows[fid][-1][0]}')
        #             all_flows.append((fid, active_flows[fid]))
        #             del active_flows[fid]
        #
        #     elif IP in pkt and UDP in pkt:
        #         # if UDP timeout has elapsed, close the old active flow and start anew
        #         if  float(pkt.time)- active_flows[fid][-1][0] > UDP_TIMEOUT:  #
        #             udp_cnt +=1
        #             if verbose and udp_cnt % 10000 ==0:
        #                 print(f'---pkt:{i}, UDP_TIMEOUT {UDP_TIMEOUT} happens for a flow {fid}, float(pkt.time) - active_flows[fid][-1][0]: {float(pkt.time) - active_flows[fid][-1][0]}')
        #             all_flows.append((fid, active_flows[fid]))
        #             del active_flows[fid]

        # if len(all_flows) > max_flows:  # avoid pcap too large
        #     # sort all flows by packet arrival time, each flow must have at least two packets
        #     flows = [(fid, *list(zip(*sorted(times_pkts)))) for fid, times_pkts in all_flows if
        #      len(times_pkts) >= max(2, num_pkt_thresh)]
        #     if len(flows) > max_flows:
        #         num_pkts = i+1
        #         print(f'num_pkts: {num_pkts}, len(flows): {len(flows)} ')
        #         break

    num_pkts = i + 1
    print(f'pkts: {i + 1}=={pkts_tcp + pkts_udp + pkts_other} <= (tcp:{pkts_tcp}, udp:{pkts_udp}, others:{pkts_other})')
    # store remained active flows
    for fid in active_flows.keys():
        all_flows.append((fid, active_flows[fid]))  # change dict to tuple

    # sort all flows by packet arrival time, each flow must have at least two packets
    flows = [(fid, *list(zip(*sorted(times_pkts)))) for fid, times_pkts in all_flows if
             len(times_pkts) >= max(2, num_pkt_thresh)]
    print(f'len(flows): {len(flows)}')
    return flows, num_pkts


def _load_pcap_to_subflows(pcap_file, num_pkt_thresh=2, interval=0.01, max_pkts=50000, max_flows=20000, verbose=True):
    '''Reads pcap and divides packets into 5-tuple flows (arrival times and sizes)

       Arguments:
         pcap_file (string) = path to pcap file
         num_pkt_thresh (int) = discards flows with fewer packets than max(2, thresh)

       Returns:
         flows (list) = [(fid, arrival times list, packet sizes list)]
    '''

    TCP_TIMEOUT = 600  # 600 seconds
    UDP_TIMEOUT = 600  # 600 seconds

    SHOWCNT = 10000  # use to control the line to print

    if interval > TCP_TIMEOUT or interval > UDP_TIMEOUT:
        print(f'be careful: interval({interval}) > TCP_TIMEOUT({TCP_TIMEOUT}) or interval > UDP_TIMEOUT({UDP_TIMEOUT})')

    # if verbose:
    #     funcparams_dict = {'pcap_file': pcap_file, 'TCP_TIMEOUT': TCP_TIMEOUT, 'UDP_TIMEOUT': UDP_TIMEOUT,
    #                        'interval': interval, 'num_pkt_thresh': num_pkt_thresh, 'max_pkts': max_pkts,
    #                        'max_flows': max_flows,
    #                        'verbose': verbose}
    #     pprint(OrderedDict(funcparams_dict), name=_load_pcap_to_subflows.__name__)

    # read packets iteratively
    active_flows = defaultdict(list)
    new_flow = {}
    interval_flow = {}
    all_flows = []
    tcp_cnt = 0
    udp_cnt = 0
    all_subflows = {'subflows': 0,
                    'removed_subflows': 0}  # 'removed_subflows: means the subflows has less than num_pkt_thresh

    tmp_c = 0  # for debug
    for i, pkt in enumerate(PcapReader(pcap_file)):
        if i % SHOWCNT == 0:
            print("Packet {}".format(i))

        current_time = float(pkt.time)

        # handle TCP packets
        if IP in pkt and TCP in pkt:
            # parse 5-tuple flow ID
            fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 6)
            # create a new active flow if one doesn't exist
            if not active_flows[fid]:
                active_flows[fid] = [(float(pkt.time), pkt)]
                new_flow[fid] = 1  # label if a flow is a new flow or it is a split (sub)flow
                interval_flow[fid] = float(pkt.time)  # store the start time of each flow, float type.
                continue
            # if this packet is a FIN, add it and close the active flow
            if pkt[
                TCP].flags.F:  # there might be some potential issues, if multi packets have F, only the first packet will be considered.
                if (float(pkt.time) - interval_flow[fid] > interval):
                    if (float(pkt.time) - active_flows[fid][-1][0] > TCP_TIMEOUT):
                        print(f'a few chance it will happen for FIN')
                        interval_flow[fid] += TCP_TIMEOUT  # accumulate from the time of the first packet of each flow
                        all_flows.append((fid, active_flows[fid]))
                        del active_flows[fid]
                        new_flow[fid] = 1
                        active_flows[fid] = [(float(pkt.time), pkt)]

                    else:
                        # note: int(np.floor(0.9)) = 0
                        interval_flow[fid] += int(np.floor((float(pkt.time) - interval_flow[
                            fid]) / interval)) * interval  # accumulate from the time of the first packet of each flow
                        all_flows.append((fid, active_flows[fid]))
                        del active_flows[fid]
                        new_flow[fid] = 0
                        active_flows[fid] = [(float(pkt.time), pkt)]

                elif (float(pkt.time) - active_flows[fid][-1][0] > TCP_TIMEOUT):
                    print(f'*** a few chance it will happen for TCP FIN ****')
                    interval_flow[fid] += TCP_TIMEOUT  # accumulate from the time of the first packet of each flow
                    all_flows.append((fid, active_flows[fid]))
                    del active_flows[fid]
                    new_flow[fid] = 1
                    active_flows[fid] = [(float(pkt.time), pkt)]

                else:   # there has some flow which duration is less than interval and timeout.
                    active_flows[fid].append((float(pkt.time), pkt))
                    if new_flow[fid] ==1: # a complete flow with FIN, however,  its duration is less than interval and timeout.
                        # print(len(active_flows[fid]))
                        all_flows.append((fid, active_flows[fid]))    # # doesn't keep the remainder
                    else:
                        tmp_c += 1
                del active_flows[fid]
                del new_flow[fid]

            # if the current time exceeds the interval[fid], close the old active flow and start anew
            elif (float(pkt.time) - interval_flow[fid] > interval):  # interval can > timeout
                if (float(pkt.time) - active_flows[fid][-1][0] > TCP_TIMEOUT):
                    if verbose:
                        print(
                            f'+++ pkt:{i}, it happens when (float(pkt.time) - interval_flow[fid]) > interval: {float(pkt.time) - interval_flow[fid]}) > {interval}, and float(pkt.time) - interval_flow[fid]) > TCP_TIMEOUT: {float(pkt.time) - interval_flow[fid]}) > {TCP_TIMEOUT}')
                    interval_flow[fid] += TCP_TIMEOUT  # accumulate from the time of the first packet of each flow
                    all_flows.append((fid, active_flows[fid]))
                    del active_flows[fid]
                    new_flow[fid] = 1
                    active_flows[fid] = [(float(pkt.time), pkt)]
                else:
                    # subflow duration; current.pkt.time-first.pkt.time > interval (this will have some issue (the split of each subflow is not correct))
                    interval_flow[fid] += int(np.floor((float(pkt.time) - interval_flow[
                        fid]) / interval)) * interval  # accumulate from the time of the first packet of each flow
                    all_flows.append((fid, active_flows[fid]))
                    del active_flows[fid]
                    new_flow[fid] = 0
                    active_flows[fid] = [(float(pkt.time), pkt)]
            elif (float(pkt.time) - active_flows[fid][-1][0] > TCP_TIMEOUT):
                if verbose:
                    print(
                        f'+++ pkt:{i}, a few chance it will happen when the preset interval {interval} > TCP_TIMEOUT {TCP_TIMEOUT}, (float(pkt.time) - interval_flow[fid]) < interval: {float(pkt.time) - interval_flow[fid]}) > {interval}, and float(pkt.time) - interval_flow[fid]) > TCP_TIMEOUT: ({float(pkt.time) - interval_flow[fid]}) > {TCP_TIMEOUT} ')
                interval_flow[fid] += TCP_TIMEOUT  # accumulate from the time of the first packet of each flow
                all_flows.append((fid, active_flows[fid]))
                del active_flows[fid]
                new_flow[fid] = 1
                active_flows[fid] = [(float(pkt.time), pkt)]
            # otherwise, add to existing flow
            else:  # (float(pkt.time) - interval_flow[fid] <= interval)
                active_flows[fid].append((float(pkt.time), pkt))

        # handle UDP packets
        elif IP in pkt and UDP in pkt:
            # parse 5-tuple flow ID
            fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 17)
            # create a new active flow if one doesn't exist
            if not active_flows[fid]:
                active_flows[fid] = [(float(pkt.time), pkt)]
                new_flow[fid] = 1
                interval_flow[fid] = float(pkt.time)  # store the start time of each flow
                continue
            # if the current time exceeds the interval[fid], close the old active flow and start anew
            if (float(pkt.time) - interval_flow[fid] > interval):
                if (float(pkt.time) - active_flows[fid][-1][0] > UDP_TIMEOUT):
                    if verbose:
                        print(
                            f'--- pkt:{i}, it happens when (float(pkt.time) - interval_flow[fid]) > interval: {float(pkt.time) - interval_flow[fid]}) > {interval}, and float(pkt.time) - interval_flow[fid]) > UDP_TIMEOUT: {float(pkt.time) - interval_flow[fid]}) > {UDP_TIMEOUT}')
                    interval_flow[fid] += UDP_TIMEOUT  # accumulate from the time of the first packet of each flow
                    all_flows.append((fid, active_flows[fid]))
                    del active_flows[fid]
                    new_flow[fid] = 1
                    active_flows[fid] = [(float(pkt.time), pkt)]
                else:
                    # subflow duration; current.pkt.time-first.pkt.time > interval (this will have some issue (the split of each subflow is not correct))
                    interval_flow[fid] += int(np.floor((float(pkt.time) - interval_flow[
                        fid]) / interval)) * interval  # accumulate from the time of the first packet of each flow
                    all_flows.append((fid, active_flows[fid]))
                    del active_flows[fid]
                    new_flow[fid] = 0
                    active_flows[fid] = [(float(pkt.time), pkt)]

            elif (float(pkt.time) - active_flows[fid][-1][0] > UDP_TIMEOUT):
                if verbose:
                    print(
                        f'--- pkt:{i}, a few chance it will happen when the preset interval {interval} > UDP_TIMEOUT {UDP_TIMEOUT}, (float(pkt.time) - interval_flow[fid]) < interval: ({float(pkt.time) - interval_flow[fid]}) < {interval}, and float(pkt.time) - interval_flow[fid]) > UDP_TIMEOUT: {float(pkt.time) - interval_flow[fid]}) > {UDP_TIMEOUT}')
                    interval_flow[fid] += UDP_TIMEOUT  # accumulate from the time of the first packet of each flow
                interval_flow[fid] += UDP_TIMEOUT  # accumulate from the time of the first packet of each flow
                all_flows.append((fid, active_flows[fid]))
                del active_flows[fid]
                new_flow[fid] = 1
                active_flows[fid] = [(float(pkt.time), pkt)]
            # otherwise add to existing flow
            else:
                active_flows[fid].append((float(pkt.time), pkt))

        # # handle timeout here again (it must be done for TIMEOUT for each active flow again).
        # keys = copy.deepcopy(list(active_flows.keys()))
        # for j, fid in enumerate(keys):
        #     # # if the TCP timeout has elapsed, close the old active flow and start anew
        #      # handle TCP packets
        #     if IP in pkt and TCP in pkt:
        #         if new_flow[fid] == 1 and float(pkt.time) - active_flows[fid][-1][0] > TCP_TIMEOUT :
        #             tcp_cnt +=1
        #             if verbose and tcp_cnt % SHOWCNT == 0:
        #                 print(f'+++ pkt:{i}, TCP_TIMEOUT {TCP_TIMEOUT} happens for a flow {fid}, float(pkt.time) - active_flows[fid][-1][0]: {float(pkt.time) - active_flows[fid][-1][0]}')
        #             interval_flow[fid] += TCP_TIMEOUT  # accumulate from the time of the first packet of each flow
        #             all_flows.append((fid, active_flows[fid]))
        #             del active_flows[fid]
        #             del new_flow[fid]
        #         elif new_flow[fid] ==0:
        #             # if verbose and tcp_cnt % SHOWCNT==0:
        #             #     print(f'+++the rest of a tcp flow {fid}, new_flow[fid]={new_flow[fid]}, len(active_flows[fid])={len(active_flows[fid])}')
        #             pass
        #
        #     elif IP in pkt and UDP in pkt:
        #         # if UDP timeout has elapsed, close the old active flow and start anew
        #         if  new_flow[fid] == 1  and float(pkt.time)- active_flows[fid][-1][0] > UDP_TIMEOUT:  #
        #             udp_cnt +=1
        #             if verbose and udp_cnt % SHOWCNT ==0:
        #                 print(f'--- pkt:{i}, UDP_TIMEOUT {UDP_TIMEOUT} happens for a flow {fid}, float(pkt.time) - active_flows[fid][-1][0]: {float(pkt.time) - active_flows[fid][-1][0]}')
        #             interval_flow[fid] += UDP_TIMEOUT
        #             all_flows.append((fid, active_flows[fid]))
        #             del active_flows[fid]
        #             del new_flow[fid]
        #         elif new_flow[fid] ==0:
        #             # if verbose and udp_cnt % SHOWCNT==0:
        #             #     print(f'---the rest of a udp flow {fid}, new_flow[fid]={new_flow[fid]}, len(active_flows[fid])={len(active_flows[fid])}')
        #             pass
        #
        # if i > max_pkts or len(all_flows) > max_flows:
        #     break
        #
    # store remained active flows,  # doesn't keep the remainder, here has some missing out of new flows.
    new_cnt = 0  # the number of new flows in active_flows
    old_cnt = 0  # the number of split flows in active_flows
    print(len(active_flows.keys()), len(new_flow.keys()), tmp_c)
    for fid in active_flows.keys():
        if new_flow[fid] == 1:
            new_cnt += 1
            all_flows.append((fid, active_flows[fid]))  # change dict to tuple
        else:
            old_cnt += 1

    print(f'new_flow in active_flows: {new_cnt}, old_flow in active_flows: {old_cnt},\n \
        Counter(new_flow.values()): {Counter(new_flow.values())}, where 1 is new_cnt, 0 is old_cnt')

    # sort all flows by packet arrival time, each flow must have at least two packets
    flows = [(fid, *list(zip(*sorted(times_pkts)))) for fid, times_pkts in all_flows if
             len(times_pkts) >= max(2, num_pkt_thresh)]
    print(f'len(flows): {len(flows)},')

    print(f'all_subflows: {len(all_flows)}, includes subflows: {len(flows)}, '
          f'removed_subflows: {len(all_flows) - len(flows)}')

    return flows


def get_flows_durations(flows):
    return [times[-1] - times[0] for fid, times, sizes in flows]


if __name__ == '__main__':
    # pcap_file = './dataset/srcIP_10.42.0.1_normal.pcap'
    # out_dir = 'output'
    #
    # sessions = pcap2sessions(pcap_file)
    # # flows = sessions2flows(sessions)
    # # print(len(flows))
    # # flows_durations = get_flows_durations(flows)
    # # intervals = np.quantile(flows_durations, q=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95])
    # # print(intervals)
    # flows = sessions2flows(sessions, interval=1.01118281)
    # print(len(flows))

    pcap_file ='./dataset/srcIP_10.42.0.119_anomaly.pcap'
    flows = _load_pcap_to_subflows(pcap_file, interval=1.0093828439712524)
    print(len(flows))

