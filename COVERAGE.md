# ARTEX packet coverage

Reference: [ThreatDefence at 354e8a3](https://github.com/ThreatDefence/agentic-attack-detections/tree/354e8a309803730b8f01fba1489aa0ea00d38ae6/frameworks/artex). Scope is ARTEX, not every framework in that repository. Counts below are separate units, not percentages of attacks detected.

## Suricata differential replay

The [comparison gate](tests/compare-source.rb) reads the pinned Git objects, not the checkout's working files. It runs both implementations on the same [956-packet fixture](tests/campaign.pcap), requires all 65 upstream SIDs to fire, and checks mapped SID, IPs, ports, protocol and EVE transaction ID where available. Separate [standalone checks](tests/replay-campaign.sh) reject unexpected application alerts. A successful comparison proves agreement on these transactions, not equivalence on all possible traffic.

| Upstream SID(s) | Local SID(s) | Evidence and control |
|---|---|---|
| 9726001-008 | 1004810 | Eight UA families; a client name in a different header is not a match. |
| 9726020-021 | 1004811 | Two placeholder URI literals; truncated literal excluded. |
| 9726022-024 | 1004812-014 | Callback argument pair and token header marker in URI or authorization. Wrong field or state excluded. No credential validation implied. |
| 9726025-026 | 1004815-016 | Exact header name and URI probe marker; longer header name excluded. |
| 9726040-042 | 1004817-018 | Console title plus static asset marker, or response realm. Body text is not a response header. |
| 9726060-061 | 1004819-020 | Three exact historical BLOODALCHEMY DNS/SNI names; suffix lookalikes excluded. Not ARTEX attribution. |
| 9726062-065 | 1004821-024 | Callback, community and toolkit DNS zones. Label boundaries and home-client direction; generic services are context only. |
| 9726066-068 | 1004825-027 | Toolkit HTTP host, test-path filename or hostname literal on TCP 8000. No proof of file execution or C2. |
| 9726500-537 | 1004830-033 | All 102 addresses/subnets in both directions: 86 medium, 16 low per indicator inventory. The four local IDs encode direction and confidence, not upstream actor labels. |

## Zeek and hunts

| Packet evidence | Standalone implementation and verification |
|---|---|
| Intel inventory | [campaign.intel](campaign.intel): 101 addresses, one subnet, 24 domains, 26 software strings, seven URLs, eight SHA-256 values. All 167 typed values compared; six native matching paths replayed, using a harmless body and test-only hash rather than distributing malware. |
| Native HTTP signals | [campaign-http.zeek](campaign-http.zeek) covers client identifiers, placeholder and callback URIs, request markers and keys, token markers, and console response titles. [local-http.rules](local-http.rules) deliberately requires `Notexist-xyz` as the final path component rather than matching arbitrary query text. |
| Resolution and contact | [local-dns.zeek](local-dns.zeek) correlates visible DNS A answers and subsequent established TCP; same client, answer TTL, five-minute cap, any port. Tested independently of HTTP and SNI. |
| Return connection | [campaign-flows.zeek](campaign-flows.zeek): after three inbound established TCP connections a server connects to the same visitor. Split-server visits cannot pool; normal mail/DNS callbacks excluded. State expires after a day without another qualifying visit. |
| Lateral traffic | Ten distinct established destinations on SMB/WinRM ports, or 25 Kerberos names and ten relevant KDC errors per source in an aligned ten-minute bucket. Controls include repeated destinations, 24 names, and irrelevant errors. Not proof of remote execution, Kerberoasting or directory replication. |
| HTTP hunts 17, 23-25 | [local-http.zeek](local-http.zeek) tests the short family burst. [hunt-http.rb](hunt-http.rb) separately evaluates reader-only vs same-host enrichment, three toolchain families in one source-hour, and at least two qualifying cadence windows. Tested with static asset, timing, local-source and 479/480-second boundaries. |
| Shared behavioral hunts | [hunt-shared.rb](hunt-shared.rb) covers callback-service DNS, model-service SNI, reader/tool pairs, distributed probing, backup paths/status/sweeps and external WSUS traffic. Shared service use, request success status and client identifiers are observations, not proof of misuse. [tests/hunt-shared.rb](tests/hunt-shared.rb) tests role, response, allowlist, cardinality and timing controls using Zeek-shaped log records; these are not all comparative PCAP tests. |

## Boundaries

- Native reference parity does not imply parity with every SIEM query. The source's ARTEX hunt numbers 1, 4, 12, 16, 20-24 and 29-31 have mixed network and non-network evidence: use the mapped IP/DNS/HTTP/TLS/file or flow sightings above only for the observed portion. A hostname or downloaded binary is not evidence of SQL execution, cloud enumeration, an installed console, or a compromised host.
- Hunts 2-3, 5-11, 13-15, 18-19, 26-28 and the host/cloud portions of 16, 20, 22 and 31 need authoritative sign-in, audit, storage, endpoint, database, or application records for their conclusions. Timing on a TCP connection is not a password-spray success; a web response does not establish an account was registered. Bracketed-paste bytes in a terminal are not normally visible to a network sensor.
- The inventory's remaining URI, string, filename, account, path, image, favicon and port values are not all standalone alerts. Known network markers with context are mapped above. Generic strings, common ports, cloud SDK identities and shared infrastructure do not independently identify ARTEX. Local host paths, registry/process data and container provenance need host telemetry. Favicon fingerprinting and joins to specific proxy/update/chat destinations are not implemented as equivalent hunts.
- Cross-worker native correlations, unseen/cached DNS, encrypted app data, unobserved handshakes and incomplete file reassembly can cause misses. HTTP response title matching in Zeek is chunk-local. Site and allowlist settings, proxy/NAT identity, historical IP reuse and legitimate tools affect specificity. Test traffic does not estimate production precision or recall.

To refresh **only** the pinned factual snapshot, run `ruby tools/refresh-indicators.rb /path/to/agentic-attack-detections`; neither refresh nor upstream access is needed to deploy or replay the standalone pack.