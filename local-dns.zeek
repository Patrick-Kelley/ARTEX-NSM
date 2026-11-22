@load base/frameworks/notice
@load base/protocols/dns

module LocalNSM;

export {
    redef enum Notice::Type += { Campaign_DNS_Query, Campaign_Address_Contact };
    const payload_hosts: set[string] = {
        "ftp.vietnam852.com", "site.vietnam852.com", "server.vietnam852.com",
        "down.zhzy999.net", "www.zhzy999.net", "ftp.zhzy999.net", "site.jiancai008.com"
    } &redef;
}

type Resolution: record { name: string; expires: time; };
global answers: table[addr, addr] of Resolution &write_expire=5min;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local name = to_lower(query);
    if ( qclass == 1 && name in payload_hosts )
        NOTICE([$note=Campaign_DNS_Query, $conn=c, $sub=name,
                $msg="DNS query for reported ARTEX campaign infrastructure",
                $identifier=cat(c$id$orig_h, "/", name)]);
    }

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    local name = to_lower(ans$query);
    if ( msg$rcode == 0 && ans$answer_type == DNS_ANS && ans$qclass == 1 && name in payload_hosts && ans$TTL > 0sec )
        answers[c$id$orig_h, a] = [$name=name, $expires=network_time() + ans$TTL];
    }

event connection_established(c: connection)
    {
    if ( [c$id$orig_h, c$id$resp_h] !in answers ) return;
    local answer = answers[c$id$orig_h, c$id$resp_h];
    if ( network_time() < answer$expires )
        NOTICE([$note=Campaign_Address_Contact, $conn=c, $sub=answer$name,
                $msg="Client established TCP to an address returned for reported campaign infrastructure",
                $identifier=cat(c$id$orig_h, "/", c$id$resp_h, "/", answer$name)]);
    }