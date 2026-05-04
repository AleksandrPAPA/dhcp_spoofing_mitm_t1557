/interface bridge set [find] dhcp-snooping=yes
/interface bridge port set [find where interface=ether2] dhcp-snooping=trusted
/interface bridge port set [find where interface=ether3] dhcp-snooping=no
/ip firewall filter add chain=input protocol=udp dst-port=67 action=drop comment="block_rogue_dhcp"
/ip firewall filter add chain=input protocol=udp src-port=67 dst-port=68 action=accept comment="allow legitimate"
