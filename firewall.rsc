/ip firewall filter
add action=drop chain=input disabled=yes in-interface-list=!noaccessrouter \
    log=yes
add action=accept chain=forward disabled=yes protocol=icmp
add action=accept chain=input connection-state=established,related disabled=\
    yes
add action=add-src-to-address-list address-list=Syn_Flooder \
    address-list-timeout=10m chain=input comment=\
    "Add Syn Flood IP to the list" connection-limit=100,32 disabled=yes \
    protocol=tcp tcp-flags=syn
add action=drop chain=input comment="Drop to syn flood list" disabled=yes \
    src-address-list=Syn_Flooder
add action=accept chain=input comment="Accept to established connections" \
    connection-state=established
add action=accept chain=input comment="Accept DNS - UDP" port=53 protocol=udp
add action=accept chain=input comment="Accept DNS - TCP" port=53 protocol=tcp
add action=add-src-to-address-list address-list=Port_Scanner \
    address-list-timeout=1w chain=input comment="port scan detect" protocol=\
    tcp psd=21,3s,3,1
add action=drop chain=input src-address-list=Port_Scanner
add action=accept chain=ICMP comment=\
    "Echo request - Avoiding Ping Flood, adjust the limit as needed" \
    icmp-options=8:0 limit=2,5:packet protocol=icmp
add action=fasttrack-connection chain=forward comment=\
    "FastTrack established and related connections" connection-state=\
    established,related hw-offload=yes
add action=accept chain=ICMP comment="Echo reply" icmp-options=0:0 protocol=\
    icmp
add action=accept chain=ICMP comment="Time Exceeded" icmp-options=11:0 \
    protocol=icmp
add action=accept chain=ICMP comment="Destination unreachable" icmp-options=\
    3:0-1 protocol=icmp
add action=drop chain=ICMP comment="Drop to the other ICMPs" protocol=icmp
add action=jump chain=input comment="Jump for icmp input flow" jump-target=\
    ICMP protocol=icmp
add action=jump chain=output comment="Jump for icmp output" jump-target=ICMP \
    protocol=icmp
add action=drop chain=input disabled=yes
add action=drop chain=forward comment="Disallow weird packets" \
    connection-state=invalid
add action=drop chain=input src-address-list=blacklist
add action=log chain=input connection-state=new dst-port=22 log-prefix=\
    "SSH Brute Force Blocked" protocol=tcp src-address-list=ssh_stage3
add action=add-src-to-address-list address-list=blacklist \
    address-list-timeout=4w chain=input comment="Block SSH 4th Attemp" \
    connection-state=new dst-port=22 protocol=tcp src-address-list=ssh_stage3
add action=add-src-to-address-list address-list=ssh_stage3 \
    address-list-timeout=1m chain=input comment="Log SSH 3rd Attemp" \
    connection-state=new dst-port=22 protocol=tcp src-address-list=ssh_stage2
add action=add-src-to-address-list address-list=ssh_stage2 \
    address-list-timeout=1m chain=input comment="Log SSH 2st Attemp" \
    connection-state=new dst-port=22 protocol=tcp src-address-list=ssh_stage1
add action=add-src-to-address-list address-list=ssh_stage1 \
    address-list-timeout=1m chain=input comment="Log SSH 1st Attemp" \
    connection-state=new dst-port=22 protocol=tcp
