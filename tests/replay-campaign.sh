#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
pcap="$root/tests/campaign.pcap"
body_hash=$(printf '%s' 'fixture-only file hash check' | shasum -a 256 | awk '{print $1}')
printf '#fields\tindicator\tindicator_type\tmeta.source\n%s\tIntel::FILE_HASH\tfixture-only\n' "$body_hash" > benign.intel
zeek -r "$pcap" "$root/campaign-intel.zeek" "$root/campaign-flows.zeek" "$root/campaign-http.zeek" LogAscii::use_json=T -e "redef Site::private_address_space_is_local=F; redef Site::local_nets += {10.0.0.0/8}; redef Intel::read_files += {\"$work/benign.intel\"};"
jq -es 'map([.["id.orig_h"],.sub // .note]) | sort == (["client identifier","probe URI","probe URI","token marker in URI","token marker in authorization","key header","probe marker","console title"] | to_entries | map(["10.22.0.\(.key+10)",.value])) + [["10.22.0.45","client identifier"],["10.22.0.90","LocalNSM::Server_Return_Connection"],["10.22.0.93","LocalNSM::Management_Port_Fanout"],["10.22.0.95","LocalNSM::KDC_Name_Failure_Burst"]] + ([range(101;108)|["192.0.2.\(.)","client identifier"]]) + (["probe URI","probe URI","probe URI","token marker in URI","token marker in authorization","probe marker","console title"]|to_entries|map(["192.0.2.\(.key+108)",.value]))' notice.log
jq -es --arg hash "$body_hash" 'map([.["seen.indicator"],.matched[]]) as $seen | [["norma/0.4","Intel::SOFTWARE"],["nginxmysql.com","Intel::DOMAIN"],["144.172.64.128","Intel::ADDR"],["92.255.57.99","Intel::SUBNET"],["ftp.vietnam852.com:88/test/winlogon.exe","Intel::URL"],[$hash,"Intel::FILE_HASH"]] - $seen == []' intel.log
awk '{print}' "$root"/campaign*.rules > combined.rules
suricata -T -S combined.rules -l . --set 'vars.address-groups.HOME_NET=[10.0.0.0/8]'
suricata -r "$pcap" -S combined.rules -l . --set 'vars.address-groups.HOME_NET=[10.0.0.0/8]'
jq -es 'map(select(.event_type=="alert" and .alert.signature_id<1004830) | [.alert.signature_id, (if .src_ip=="198.51.100.10" or .src_ip=="10.22.0.200" then .dest_ip else .src_ip end)]) | sort == ([range(10;28) | [1004800+.,"10.22.0.\(.)"]] + [[1004810,"10.22.0.45"],[1004825,"10.22.0.46"],[1004826,"10.22.0.46"]] + [range(101;108)|[1004810,"192.0.2.\(.)"]] + ([11,11,12,13,14,16,17]|to_entries|map([1004800+.value,"192.0.2.\(.key+108)"])) | sort)' eve.json
awk -F '\t' '$2=="Intel::ADDR" || $2=="Intel::SUBNET" {address=$1;sub(/\.0\/24$/,".1",address);base=($3~/medium$/?1004830:1004832);print base,address;print base+1,address}' "$root/campaign.intel" | sort > expected.txt
jq -r 'select(.event_type=="alert" and .alert.signature_id>=1004830 and (.src_ip=="10.22.0.80" or .dest_ip=="10.22.0.80" or .src_ip=="10.22.0.81" or .dest_ip=="10.22.0.81")) | "\(.alert.signature_id) \(if (.src_ip|startswith("10.22.")) then .dest_ip else .src_ip end)"' eve.json | sort > actual.txt
diff -u expected.txt actual.txt
jq -es 'all(.[]; .event_type!="alert" or .alert.signature_id<1004830 or ([.src_ip,.dest_ip] | any(test("^10\\.22\\.0\\.8[0-3]$"))))' eve.json
echo 'PASS: campaign signatures, six intel types, IP membership and behavioral controls'