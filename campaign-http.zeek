@load base/frameworks/notice
@load base/protocols/http

module LocalNSM;

export {
    redef enum Notice::Type += { Campaign_HTTP_Marker };
}

const unsigned_marker = /eyJhbGciOiJub25lIn0\.|eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0\.|eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0\./;

function http_sighting(c: connection, kind: string)
    {
    NOTICE([$note=Campaign_HTTP_Marker, $sub=kind, $conn=c,
            $msg=fmt("Reported campaign HTTP marker: %s", kind),
            $identifier=cat(c$id$orig_h, "/", c$id$resp_h, "/", kind)]);
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if ( /zzz-nonexistent-xyz123|zzz_nonexistent_abc\.txt|code=AAAA&state=notvalidb64!!/ in original_URI )
        http_sighting(c, "probe URI");
    if ( /artex_write_probe|artx_persist_ok|artex_control_marker_zz9q|artex-probe-/ in to_lower(original_URI) )
        http_sighting(c, "probe marker");
    if ( unsigned_marker in original_URI ) http_sighting(c, "token marker in URI");
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig ) return;
    if ( name == "X-ARTX-KEY" ) http_sighting(c, "key header");
    if ( name == "AUTHORIZATION" && unsigned_marker in value ) http_sighting(c, "token marker in authorization");
    if ( name == "USER-AGENT" && (/artex-(worker|readonly|pentest|audit|verify|spawn|enrich)\/|scopeweaver/ in to_lower(value) || /ARTeX|artex-i21861-canary|Mozilla\/5\.0 \(ARTEX\)|ArtExVerify\/|ArtEx\/1\.0|spa-api-recon/ in value) )
        http_sighting(c, "client identifier");
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! is_orig && /<title>(ARTEX|ScopeWeaver|LUCK)[ :<\-]/ in data )
        http_sighting(c, "console title");
    }