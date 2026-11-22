@load base/frameworks/notice
@load base/protocols/krb

module LocalNSM;

export {
    redef enum Notice::Type += { Server_Return_Connection, Management_Port_Fanout, KDC_Name_Failure_Burst };
    const monitored_servers: set[subnet] = {} &redef;
}

global visits: table[addr, addr] of count &default=0 &write_expire=1day;
global destinations: table[addr, count] of set[addr] &create_expire=10min;
type KdcWindow: record { names: set[string]; errors: count; };
global kdc_windows: table[addr, count] of KdcWindow &create_expire=10min;

function managed(host: addr): bool
    {
    return |monitored_servers| == 0 ? Site::is_local_addr(host) : host in monitored_servers;
    }

event connection_established(c: connection)
    {
    local client = c$id$orig_h;
    local server = c$id$resp_h;
    if ( managed(server) && ! Site::is_local_addr(client) )
        visits[client, server] = visits[client, server] < 3 ? visits[client, server]+1 : 3;
    if ( managed(client) && ! Site::is_local_addr(server) && visits[server, client] >= 3 && c$id$resp_p !in set(25/tcp, 53/tcp) )
        NOTICE([$note=Server_Return_Connection, $conn=c, $msg="Server established TCP back to a prior repeated visitor", $identifier=cat(client,"/",server)]);

    if ( c$id$resp_p !in set(445/tcp, 5985/tcp, 5986/tcp) ) return;
    local epoch = double_to_count(time_to_double(network_time()) / 600.0);
    if ( [client, epoch] !in destinations ) destinations[client, epoch] = set();
    if ( |destinations[client, epoch]| >= 10 ) return;
    add destinations[client, epoch][server];
    if ( |destinations[client, epoch]| == 10 )
        NOTICE([$note=Management_Port_Fanout, $conn=c, $msg="Client established TCP to ten destinations on SMB or WinRM ports in ten minutes", $identifier=cat(client)]);
    }

function kdc_observation(c: connection, name: string, failure: bool)
    {
    local client = c$id$orig_h;
    local epoch = double_to_count(time_to_double(network_time()) / 600.0);
    if ( [client, epoch] !in kdc_windows )
        {
        local names: set[string] = set();
        kdc_windows[client, epoch] = [$names=names, $errors=0];
        }
    local window = kdc_windows[client, epoch];
    if ( |window$names| >= 25 && window$errors >= 10 ) return;
    if ( name != "" && |window$names| < 25 ) add window$names[to_lower(name)];
    if ( failure && window$errors < 10 ) ++window$errors;
    if ( |window$names| == 25 && window$errors == 10 )
        NOTICE([$note=KDC_Name_Failure_Burst, $conn=c, $msg="Client observed with 25 Kerberos names and ten unknown-principal or pre-authentication errors in ten minutes", $identifier=cat(client)]);
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request)
    {
    if ( msg?$client_name ) kdc_observation(c, msg$client_name, F);
    }

event krb_error(c: connection, msg: KRB::Error_Msg)
    {
    if ( msg$error_code == 6 || msg$error_code == 24 )
        kdc_observation(c, msg?$client_name ? msg$client_name : "", T);
    }