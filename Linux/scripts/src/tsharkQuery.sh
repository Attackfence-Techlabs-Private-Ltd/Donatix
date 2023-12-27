#!/bin/bash

batch_size=1000  # Adjust the batch size as needed
total_packets=10000  # Set the total number of packets you want to capture
duration_per_batch=300  # Set the duration (in seconds) for each capture batch


# Loop until the total number of packets is reached
while [ $total_packets -gt 0 ]; do
    # Capture a batch of packets
    # tshark query to capture the dns records based on the batch size 
    # and then the python script will insert the data in sqlite3 db
    # unbuffer tshark -i w;p0s20f3 -c $batch_size -f "(udp src port 53) or (udp src port 5353) or (udp dst port 53) or (udp dst port 5353)" -n -T fields -e frame.interface_name -e _ws.col.Time -e ip.dst -e udp.dstport -e ip.src -e udp.srcport -e dns.flags.rcode -e dns.qry.name -e dns.qry.name.len -e dns.count.labels -e dns.qry.type -e dns.resp.name -e dns.resp.type -e dns.resp.ttl -e dns.resp.len -e dns.flags.response -e dns.resp.class -e dns.rr.udp_payload_size -e dns.a -e dns.aaaa -e dns.txt -e dns.ptr.domain_name -E header=y -E separator="," -E occurrence=f -E aggregator="|" -t ad | ./noname.py

    # Alternatively, you can capture for a specific duration
    # tshark query to capture the dns records based on the duration 
    # and then the python script will insert the data in sqlite3 db
    unbuffer tshark -i wlp0s20f3 -a duration:$duration_per_batch -f "(udp src port 53) or (udp src port 5353) or (udp dst port 53) or (udp dst port 5353)" -n -T fields -e frame.interface_name -e _ws.col.Time -e ip.dst -e udp.dstport -e ip.src -e udp.srcport -e dns.flags.rcode -e dns.qry.name -e dns.qry.name.len -e dns.count.labels -e dns.qry.type -e dns.resp.name -e dns.resp.type -e dns.resp.ttl -e dns.resp.len -e dns.rr.udp_payload_size -e dns.a -e dns.aaaa -e dns.txt -e dns.ptr.domain_name -E header=y -E separator="," -E occurrence=f -E aggregator="|" -t ad | ./noname.py

    # Decrement the total number of packets
    total_packets=$((total_packets - batch_size))

    # Sleep for a short duration before capturing the next batch
    sleep 1
done

