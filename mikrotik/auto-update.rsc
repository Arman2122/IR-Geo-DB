# RouterOS self-updating installer
# Entries: 1
# Built:   2026-08-08 04:35:18 UTC   Release: v2026.08.08
# Sources: n/a
# Project: https://github.com/Arman2122/IR-Geo-DB
#
/system script
add name=IR-Geo-Update policy=ftp,read,write,test,policy source={
:local url "https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mikrotik/ir-ipv4-reset.rsc"
:do { /file remove [find name="ir-geo.rsc"] } on-error={}
:do { /tool fetch url=$url mode=https dst-path="ir-geo.rsc" } on-error={
  :log error "IR-Geo: fetch failed, address list left untouched"
  :error "fetch failed" }
:delay 5s
:if ([:len [/file find name="ir-geo.rsc"]] = 0) do={ :error "no file" }
:if ([/file get [find name="ir-geo.rsc"] size] < 20000) do={
  :log warning "IR-Geo: file too small, refusing to import"
  :error "short file" }
/import file-name="ir-geo.rsc"
:log info ("IR-Geo: " . [/ip firewall address-list print count-only where list=IR] . " prefixes loaded")
}

/system scheduler
add name=IR-Geo-Schedule interval=1d start-time=04:00:00 \
    on-event=IR-Geo-Update policy=ftp,read,write,test
