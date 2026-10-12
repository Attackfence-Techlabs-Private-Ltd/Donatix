# PowerShell script to capture DNS records using tshark.exe and insert data into SQLite3 DB
$durationPerBatch = 300  # Set the duration (in seconds) for each capture batch
$pythonScriptPath = Join-Path $PSScriptRoot "..\src\noname.py"
# tshark writes UTF-8; without this, non-ASCII characters in names reach the database as "?"
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Text.UTF8Encoding]::new($false)
$env:PYTHONIOENCODING = "utf-8"
# Capture on the interface that carries the default route
$interface = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias
# Loop until the total number of packets is reached
while ($true) {
    # Capture a batch of packets
    # tshark query to capture the DNS records based on the batch size 
    # and then the Python script will insert the data into SQLite3 DB
    & "C:\Program Files\Wireshark\tshark.exe" -i $interface -l -a duration:$durationPerBatch -f "(udp src port 53) or (udp src port 5353) or (udp dst port 53) or (udp dst port 5353)" -n -T fields -e frame.interface_name -e ip.dst -e udp.dstport -e ip.src -e udp.srcport -e dns.flags.rcode -e dns.qry.name -e dns.qry.name.len -e dns.count.labels -e dns.qry.type -e dns.resp.name -e dns.resp.type -e dns.resp.ttl -e dns.resp.len -e dns.rr.udp_payload_size -e dns.a -e dns.aaaa -e dns.txt -e dns.ptr.domain_name -E header=y -E separator="," -E occurrence=f -E aggregator="|" 2>$null |
        python $pythonScriptPath | Out-Null
    # Nothing is written to the console: a click in the window freezes it and blocks whoever writes to it

    # Sleep for a short duration before capturing the next batch
    Start-Sleep -Seconds 1
}
