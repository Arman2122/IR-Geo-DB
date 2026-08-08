# RFC-reserved and private address space — RouterOS ipv4 address-list PRIVATE (append)
# Entries: 14
# Built:   2026-08-08 04:35:18 UTC   Release: v2026.08.08
# Sources: RFC 1918 / 5735 / 6598 / 4193
# Project: https://github.com/Arman2122/IR-Geo-DB
#
/ip firewall address-list
add address=0.0.0.0/8 list=PRIVATE
add address=10.0.0.0/8 list=PRIVATE
add address=100.64.0.0/10 list=PRIVATE
add address=127.0.0.0/8 list=PRIVATE
add address=169.254.0.0/16 list=PRIVATE
add address=172.16.0.0/12 list=PRIVATE
add address=192.0.0.0/24 list=PRIVATE
add address=192.0.2.0/24 list=PRIVATE
add address=192.88.99.0/24 list=PRIVATE
add address=192.168.0.0/16 list=PRIVATE
add address=198.18.0.0/15 list=PRIVATE
add address=198.51.100.0/24 list=PRIVATE
add address=203.0.113.0/24 list=PRIVATE
add address=224.0.0.0/3 list=PRIVATE
