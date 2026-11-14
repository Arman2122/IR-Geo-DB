# RFC-reserved and private address space — RouterOS ipv6 address-list PRIVATE (append)
# Entries: 4
# Built:   2026-11-14 10:45:30 UTC   Release: v2026.11.14
# Sources: RFC 1918 / 5735 / 6598 / 4193
# Project: https://github.com/Arman2122/IR-Geo-DB
#
/ipv6 firewall address-list
add address=::/127 list=PRIVATE
add address=fc00::/7 list=PRIVATE
add address=fe80::/10 list=PRIVATE
add address=ff00::/8 list=PRIVATE
