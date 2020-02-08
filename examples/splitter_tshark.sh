

#"""
#  https://ask.wireshark.org/question/2405/how-do-i-extract-the-individual-flows-from-the-total-packets-in-a-pcap-file/
#  https://stackoverflow.com/questions/49667663/how-can-i-extract-flows-instead-of-packets-with-tshark
#"""

pcap_file='./dataset/srcIP_10.42.0.1_normal.pcap'
out_dir='output'

### split pcap into tcp flows
for idx_stream in `tshark -r $pcap_file -T fields -e tcp.stream | sort -n | uniq`
do
    echo $idx_stream
    tshark -r $pcap_file -w $out_dir/flow-$idx_stream.pcap -Y "tcp.stream==$idx_stream"    # single direction
#    tshark -r $pcap_file -w $out_dir/session-$idx_stream.pcap -R -2 "tcp.stream==$idx_stream"    # bidirection
#    tshark -r $pcap_file -z io,stat,300,"tcp.stream==$stream"     # split flow into subflow with interval 300s
done


### split pcap intot udp flows
# tshark -r ./dataset/srcIP_10.42.0.1_normal.pcap -T fields -e udp.stream -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -E header=y -E separator=,

for idx_stream in `tshark -r $pcap_file -T fields -e udp.stream -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e ip.proto | sort -n | uniq`
do
    echo $idx_stream
    tshark -r $pcap_file -w $out_dir/flow-$idx_stream.pcap -Y "udp.stream==$idx_stream"    # single direction
#    tshark -r $pcap_file -w $out_dir/session-$idx_stream.pcap -R -2 "udp.stream==$idx_stream"    # bidirection
#    tshark -r $pcap_file -z io,stat,300,"udp.stream==$stream"     # split flow into subflow with interval 300s
done