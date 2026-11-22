import ipaddress
import sys
from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap
from scapy.layers.tls.all import ServerName, TLS, TLSClientHello, TLS_Ext_ServerName
from scapy.layers.kerberos import KRB_ERROR, PrincipalName
from scapy.asn1.asn1 import ASN1_GENERAL_STRING

packets = []
outside = '198.51.100.10'


def add(source, dest, segment):
    packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=source, dst=dest) / segment
    packet.time = 1795000000 + len(packets) / 100
    packets.append(packet)


def tcp(client, server, port, request=b'', response=b''):
    sport = 30000 + len(packets)
    for reverse, flags, seq, ack, data in [
        (False, 'S', 100, 0, b''), (True, 'SA', 500, 101, b''), (False, 'A', 101, 501, b''),
        (False, 'PA', 101, 501, request), (True, 'PA', 501, 101 + len(request), response),
        (False, 'FA', 101 + len(request), 501 + len(response), b''),
        (True, 'FA', 501 + len(response), 102 + len(request), b''),
        (False, 'A', 102 + len(request), 502 + len(response), b''),
    ]:
        segment = TCP(sport=port if reverse else sport, dport=sport if reverse else port, flags=flags, seq=seq, ack=ack) / data
        add(server if reverse else client, client if reverse else server, segment)


def http(case, path='/', header='', host='example.test', response_header='', body='', inbound=False):
    request = f'GET {path} HTTP/1.1\r\nHost: {host}\r\n{header}\r\n\r\n'.encode()
    response = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\n{response_header}\r\n\r\n{body}'.replace('\r\n\r\n\r\n','\r\n\r\n').encode()
    client, server = (f'192.0.2.{case}', '10.22.0.200') if inbound else (f'10.22.0.{case}', outside)
    tcp(client, server, 80, request, response)


marker = 'eyJhbGciOiJub25lIn0.'
http(10, header='User-Agent: ARTEX-worker/1.0')
http(11, '/zzz-nonexistent-xyz123')
http(12, '/?code=AAAA&state=notvalidb64!!')
http(13, '/?marker=' + marker)
http(14, header='Authorization: Bearer ' + marker)
http(15, header='X-ARTX-KEY: fixture')
http(16, '/ARTX_PERSIST_OK')
http(17, body='<title>ScopeWeaver</title>/_next/static')
http(18, response_header='WWW-Authenticate: Basic realm="ARTEX"')
http(25, host='cdn.zhzy999.net')
http(26, '/test/smss.exe')
http(40, '/smss.exe?ref=/zzz-nonexistent-xyz12', 'X-ARTX-KEY-Test: ' + marker, host='cdn.zhzy999.net.example.org', body='<title>Example</title>/_next/static')
http(41, header='X-Client: ARTEX-worker/1.0', response_header='X-ARTX-KEY: sample')
http(42, '/?code=AAAA&state=other', header='Authorization: fixture')
http(43, '/ARTX_PERSIST_NO', body='<title>Example</title>realm="ARTEX"')
http(44, '/test/smss.exe.bak')
http(45, header='User-Agent: norma/0.4')
http(46, '/test/winlogon.exe', host='ftp.vietnam852.com:88')
for case, name in [(19, 'nginxmysql.com'), (21, 'one.webhook.site'), (22, 'artx17.dnslog.cn'), (23, 'staging.artex.lol'), (24, 'cdn.zhzy999.net'), (50, 'nginxmysql.com.test'), (51, 'notwebhook.site'), (52, 'normal.dnslog.cn'), (53, 'notartex.lol'), (54, 'zhzy999.net.test')]:
    add(f'10.22.0.{case}', outside, UDP(sport=50000+case, dport=53) / DNS(id=case, qd=DNSQR(qname=name)))
for case, name in [(20, 'nginxmysql.com'), (55, 'nginxmysql.com.test')]:
    extension = TLS_Ext_ServerName(servernames=[ServerName(servername=name.encode())])
    tcp(f'10.22.0.{case}', outside, 443, bytes(TLS(msg=[TLSClientHello(gmt_unix_time=1, random_bytes=bytes(28), ciphers=[47], ext=[extension])])))
for case, port, text in [(27, 8000, b'server.vietnam852.com'), (56, 8001, b'server.vietnam852.com'), (57, 8000, b'example.test')]:
    tcp(f'10.22.0.{case}', outside, port, text)

intel = Path(__file__).resolve().parents[1] / 'campaign.intel'
for row in intel.read_text().splitlines()[1:]:
    value, kind, source = row.split('\t')
    if kind not in ('Intel::ADDR', 'Intel::SUBNET'):
        continue
    address = str(next(ipaddress.ip_network(value).hosts()))
    home = '10.22.0.80' if source.endswith('medium') else '10.22.0.81'
    add(home, address, UDP(sport=40000, dport=40001))
    add(address, home, UDP(sport=40002, dport=40003))
tcp('10.22.0.82', '144.172.64.128', 4242)
tcp('10.22.0.83', '92.255.57.99', 4242)
for visitor, targets in [(90, [90, 90, 90]), (91, [91, 91, 92])]:
    for target in targets:
        tcp(f'192.0.2.{visitor}', f'10.22.0.{target}', 443)
    tcp(f'10.22.0.{visitor}', f'192.0.2.{visitor}', 53)
    tcp(f'10.22.0.{visitor}', f'192.0.2.{visitor}', 4242)
for client, distinct in [(93, 10), (94, 9)]:
    for index in range(12):
        tcp(f'10.22.0.{client}', f'10.23.0.{1 + index % distinct}', [445, 5985, 5986][index % 3])
for client, distinct, error in [(95, 25, 6), (96, 24, 24), (97, 25, 7)]:
    for index in range(25):
        name = PrincipalName(nameType=1, nameString=[ASN1_GENERAL_STRING(f'fixture{index % distinct}')])
        message = KRB_ERROR(stime='20261122000000Z', errorCode=error, crealm='EXAMPLE.TEST', realm='EXAMPLE.TEST', cname=name,
                            sname=PrincipalName(nameType=2, nameString=[ASN1_GENERAL_STRING('fixture-service')]))
        add(f'10.22.0.{client}', '10.23.0.88', UDP(sport=47000+index, dport=88))
        add('10.23.0.88', f'10.22.0.{client}', UDP(sport=88, dport=47000+index) / bytes(message))
http(98, body='fixture-only file hash check')
for case, agent in enumerate(['artex-audit/1.0', 'Mozilla/5.0 ARTeX', 'artex-i21861-canary', 'Mozilla/5.0 (ARTEX)',
                              'ArtExVerify/1.0', 'ScopeWeaver', 'spa-api-recon'], 101):
    http(case, header='User-Agent: ' + agent, inbound=True)
http(108, '/zzz_nonexistent_abc.txt', inbound=True)
http(109, '/zzz-nonexistent-xyz123', inbound=True)
http(110, '/?code=AAAA&state=notvalidb64!!', inbound=True)
http(111, '/?marker=' + marker, inbound=True)
http(112, header='Authorization: fixture ' + marker, inbound=True)
http(113, '/ARTEX_WRITE_PROBE', inbound=True)
http(114, body='<title>ARTEX</title>/_next/static', inbound=True)
wrpcap(sys.argv[1], packets)