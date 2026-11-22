@load base/frameworks/notice
@load base/protocols/http

module LocalNSM;

export {
    redef enum Notice::Type += { Replay_Nonce_Header, Implant_Header_Pair, Client_Family_Burst };
}

type Burst: record { requests: count &default=0; families: set[string]; };
global bursts: table[addr, addr, count] of Burst &create_expire=2min;

function client_family(agent: string): string
    {
    local value = to_lower(agent);
    if ( /^(boto3|aws-cli|aws-sdk)/ in value ) return "aws";
    if ( /(python-requests|python-urllib|aiohttp|httpx)/ in value ) return "python";
    if ( /^curl\// in value ) return "curl";
    if ( /^norma/ in value ) return "norma";
    if ( /^go-http-client/ in value ) return "go";
    if ( /(nuclei|sqlmap|ffuf|katana|gobuster|nikto)/ in value ) return "scanner";
    if ( /^mozilla\/5\.0/ in value ) return "browser";
    return "";
    }

event HTTP::log_http(rec: HTTP::Info)
    {
    if ( ! rec?$user_agent || Site::is_local_addr(rec$id$orig_h) || ! Site::is_local_addr(rec$id$resp_h) )
        return;
    local family = client_family(rec$user_agent);
    if ( family == "" ) return;
    local minute = double_to_count(time_to_double(rec$ts) / 60.0);
    if ( [rec$id$orig_h, rec$id$resp_h, minute] !in bursts )
        bursts[rec$id$orig_h, rec$id$resp_h, minute] = [$families=set(family)];
    local state = bursts[rec$id$orig_h, rec$id$resp_h, minute];
    ++state$requests;
    add state$families[family];
    if ( state$requests >= 20 && |state$families| >= 3 )
        NOTICE([$note=Client_Family_Burst, $id=rec$id, $uid=rec$uid,
                $msg=fmt("External client made %d requests from %d recognized HTTP client families in one minute", state$requests, |state$families|),
                $identifier=cat(rec$id$orig_h, "/", rec$id$resp_h), $suppress_for=1min]);
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( is_orig && name == "X-ARTEX-REPLAY-NONCE" )
        NOTICE([$note=Replay_Nonce_Header, $conn=c,
                $msg="Request carried the ARTEX replay nonce header",
                $identifier=cat(c$id$orig_h, "/", c$id$resp_h)]);
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( ! is_orig )
        return;

    local implant = F;
    local session = F;
    for ( index in hlist )
        {
        local header = hlist[index];
        if ( header$name == "X-IMPLANT-TOKEN" && |header$value| > 0 )
            implant = T;
        if ( header$name == "X-SESSION-TOKEN" && /^[0-9a-fA-F]{64}$/ in header$value )
            session = T;
        }
    if ( implant && session )
        NOTICE([$note=Implant_Header_Pair, $conn=c,
                $msg="Request carried the reported CyberStrikeAI token-header pair",
                $identifier=cat(c$id$orig_h, "/", c$id$resp_h)]);
    }