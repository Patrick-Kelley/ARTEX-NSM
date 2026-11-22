import sys
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP, wrpcap
from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName, ServerName

session_header = 'X-Session-Token: ' + 'a' * 64
transactions = [
    ('/bucket/Notexist-xyz?version=2', 'x-ArTeX-Replay-Nonce: demo', ''),
    ('/normal', 'X-Other: X-ARTEX-Replay-Nonce', 'X-ARTEX-Replay-Nonce: demo'),
    ('/normal?ref=/Notexist-xyz', 'X-ARTEX-Replay-Nonce-Test: demo', ''),
    ('/Notexist-xyz-more', session_header, ''),
    ('/normal', session_header + '\r\nx-implant-token: example', ''),
    ('/normal', 'X-Implant-Token: example\r\nX-Session-Token: short', ''),
]
packets = []
resolver = '198.51.100.53'
for host, name, ttl in [(30, 'FTP.Vietnam852.com', 60), (31, 'ftp.vietnam852.com.example.org', 60),
                        (32, 'site.jiancai008.com', 1), (33, 'down.zhzy999.net', None)]:
    client = f'192.0.2.{host}'
    query = DNSQR(qname=name)
    request = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=client, dst=resolver) / UDP(sport=53000+host, dport=53) / DNS(id=host, rd=1, qd=query)
    request.time = 1795000000 + len(packets) / 100
    packets.append(request)
    if ttl is not None:
        answer = DNSRR(rrname=name, ttl=ttl, rdata='198.51.100.10')
        response = Ether(src='02:00:00:00:00:02', dst='02:00:00:00:00:01') / IP(src=resolver, dst=client) / UDP(sport=53, dport=53000+host) / DNS(id=host, qr=1, rd=1, ra=1, qd=query, an=answer)
        response.time = 1795000000 + len(packets) / 100
        packets.append(response)
cases = [(f'192.0.2.{number}', *transaction) for number, transaction in enumerate(transactions, 1)]
for host, total, families in [(7, 20, 3), (8, 19, 3), (9, 20, 2)]:
    agents = ['curl/8', 'python-requests/2', 'Go-http-client/1'][:families]
    for index in range(total):
        cases.append((f'192.0.2.{host}', '/normal', 'User-Agent: ' + agents[index % families], ''))
tls_names = ['ftp.vietnam852.com', 'carbonato-proxy-zeta.vercel.app', 'ftp.vietnam852.com.example.org', 'unrelated.vercel.app']
cases.extend((f'192.0.2.{20 + index}', None, name, '') for index, name in enumerate(tls_names))
cases.extend((f'192.0.2.{host}', 'tcp-only', '', '') for host in range(30, 35))
for number, (client, path, request_headers, response_headers) in enumerate(cases, 1):
    server = '198.51.100.10'
    port = 40000 + number
    request = f'GET {path} HTTP/1.1\r\nHost: example.test\r\n{request_headers}\r\n\r\n'.encode()
    response = ('HTTP/1.1 204 No Content\r\n' + (response_headers + '\r\n' if response_headers else '') + '\r\n').encode()
    service = 80
    if path == 'tcp-only':
        service = 4242
        request, response = b'', b''
    if path is None:
        service = 443
        extension = TLS_Ext_ServerName(servernames=[ServerName(servername=request_headers.encode())])
        request = bytes(TLS(msg=[TLSClientHello(gmt_unix_time=1795000000, random_bytes=bytes(28), ciphers=[0x002f], ext=[extension])]))
        response = b''
    for reverse, flags, seq, ack, payload in [
        (False, 'S', 100, 0, b''), (True, 'SA', 500, 101, b''),
        (False, 'A', 101, 501, b''), (False, 'PA', 101, 501, request),
        (True, 'PA', 501, 101 + len(request), response),
        (False, 'FA', 101 + len(request), 501 + len(response), b''),
        (True, 'FA', 501 + len(response), 102 + len(request), b''),
        (False, 'A', 102 + len(request), 502 + len(response), b''),
    ]:
        packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=server if reverse else client, dst=client if reverse else server) / TCP(sport=service if reverse else port, dport=port if reverse else service, flags=flags, seq=seq, ack=ack) / payload
        packet.time = 1795000000 + len(packets) / 100
        packets.append(packet)
wrpcap(sys.argv[1], packets)