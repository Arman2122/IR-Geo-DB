# Iranian CDN and hosting provider ranges — RouterOS ipv6 address-list IR_CDN (replace)
# Entries: 28
# Built:   2026-10-24 08:19:30 UTC   Release: v2026.10.24
# Sources: ArvanCloud, Sotoon, Derak, IranServer, MizbanCloud, ParsPack, RIPE NCC RIS routing data
# Project: https://github.com/Arman2122/IR-Geo-DB
#
/ipv6 firewall address-list
remove [find list=IR_CDN dynamic=no]
add address=2a01:4f8:c0:2da6::/64 list=IR_CDN
add address=2a04:2f00:1::/48 list=IR_CDN
add address=2a04:2f00:2::/47 list=IR_CDN
add address=2a04:2f00:d::/48 list=IR_CDN
add address=2a04:2f00:e::/48 list=IR_CDN
add address=2a04:2f00:ff01::/64 list=IR_CDN
add address=2a04:2f00:ff02::/64 list=IR_CDN
add address=2a04:2f00:ff03::/64 list=IR_CDN
add address=2a04:2f00:ff06::/64 list=IR_CDN
add address=2a04:2f00:ff08::/64 list=IR_CDN
add address=2a04:2f00:ff09::/64 list=IR_CDN
add address=2a04:2f01:1::/48 list=IR_CDN
add address=2a04:2f01:2::/47 list=IR_CDN
add address=2a04:2f01:4::/48 list=IR_CDN
add address=2a05:ab80::/48 list=IR_CDN
add address=2a05:ab80:100::/48 list=IR_CDN
add address=2a05:ab80:200::/48 list=IR_CDN
add address=2a07:3900::/29 list=IR_CDN
add address=2a0c:a7c6:4::/48 list=IR_CDN
add address=2a0c:a7c6:8::/46 list=IR_CDN
add address=2a0c:a7c6:1000::/36 list=IR_CDN
add address=2a0c:a7c7::/40 list=IR_CDN
add address=2a0d:4ac0::/40 list=IR_CDN
add address=2a0f:94c0:200::/40 list=IR_CDN
add address=2a10:5740::/47 list=IR_CDN
add address=2a10:5740:2::/48 list=IR_CDN
add address=2a10:a440::/29 list=IR_CDN
add address=2a10:f980::/29 list=IR_CDN
