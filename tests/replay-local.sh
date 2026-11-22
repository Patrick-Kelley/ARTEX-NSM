#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
pcap="$root/tests/local-http.pcap"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

zeek --version
zeek -r "$pcap" "$root/local-http.zeek" "$root/local-dns.zeek" LogAscii::use_json=T -e 'redef Site::private_address_space_is_local = F; redef Site::local_nets += { 198.51.100.10/32 };'
jq -es 'map(select(.note | startswith("LocalNSM::")) | [.note, .["id.orig_h"]]) | sort == [["LocalNSM::Campaign_Address_Contact","192.0.2.30"],["LocalNSM::Campaign_DNS_Query","192.0.2.30"],["LocalNSM::Campaign_DNS_Query","192.0.2.32"],["LocalNSM::Campaign_DNS_Query","192.0.2.33"],["LocalNSM::Client_Family_Burst","192.0.2.7"],["LocalNSM::Implant_Header_Pair","192.0.2.5"],["LocalNSM::Replay_Nonce_Header","192.0.2.1"]]' notice.log
jq -es 'map(select(.note == "LocalNSM::Campaign_Address_Contact") | [.sub, .["id.resp_h"], .["id.resp_p"]]) == [["ftp.vietnam852.com","198.51.100.10",4242]]' notice.log

suricata -V
awk '{print}' "$root/local-http.rules" "$root/local-sni.rules" "$root/local-dns.rules" > local.rules
suricata -T -S "$work/local.rules" -l "$work"
suricata -r "$pcap" -S "$work/local.rules" -l "$work"
jq -es 'map(select(.event_type == "alert") | [.alert.signature_id,.src_ip]) | sort == [[1004801,"192.0.2.1"],[1004802,"192.0.2.1"],[1004803,"192.0.2.20"],[1004804,"192.0.2.21"],[1004805,"192.0.2.30"],[1004805,"192.0.2.32"],[1004805,"192.0.2.33"]]' eve.json
echo 'PASS: standalone Zeek and Suricata replay'