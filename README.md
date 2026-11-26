# ARTEX-NSM

ARTEX-NSM is a standalone set of network detections for Zeek and Suricata. It observes DNS lookups, subsequent TCP connections, TLS server names, and HTTP client behavior associated with reported campaigns. A match describes what the sensor saw; it does not establish which tool or operator sent the traffic.

**Coverage baseline:** All 65 pinned upstream ARTEX Suricata signatures fired on the comparison capture, with a corresponding local finding on each directed flow/transaction. The standalone Zeek intel snapshot matches all 167 upstream indicator/type pairs. See the [coverage matrix](COVERAGE.md) for mapping, intentional differences, and the limits of that claim.

## Deploy

The [November 25 Microsoft report mapping](COVERAGE.md#microsoft-threat-intelligence-november-25-2026) adds versioned default-client sightings, a source-minute path/error burst hunt, and server-scoped webhook DNS, HTTP and TLS observations. These findings are leads for investigation, not actor attribution.

Load [campaign.zeek](campaign.zeek) in Zeek. Configure `Site::local_nets` and optionally `LocalNSM::monitored_servers`. Inspect `notice.log` for behaviors and `intel.log` for sightings; use JSON logs for the offline hunts. Intel matching enables hashing of visible files, so baseline CPU cost before production rollout. State for the native behavioral correlations is per worker.

Load **all five** Suricata rule files: [campaign.rules](campaign.rules), [campaign-ip.rules](campaign-ip.rules), [local-http.rules](local-http.rules), [local-sni.rules](local-sni.rules), and [local-dns.rules](local-dns.rules). Set `HOME_NET` and `EXTERNAL_NET`, enable EVE alerts and check local SID allocation. Historical/shared addresses are hunt context, not a recommended blocklist.

Optional retrospective hunts consume bounded, non-duplicated Zeek JSON logs. Supply up to seven days for cadence or fourteen days for reader/toolchain hunts; memory use grows with the input window. Set site-specific CIDRs. Combine log shards of the **same type** from the same investigation window.

```sh
LOCAL_NETS=10.0.0.0/8 ruby hunt-http.rb http.log
LOCAL_NETS=10.0.0.0/8 SERVER_NETS=10.1.0.0/16 ruby hunt-shared.rb http http.log
```

The shared hunt also accepts `dns`, `ssl`, or `conn` and the corresponding JSON log. Set `ALLOWED_AI_NETS` to exclude authorized model API clients. Outputs are JSON lines and do not include tokens or request bodies.

## Additional Local Signals

- [local-dns.zeek](local-dns.zeek) and [local-dns.rules](local-dns.rules): an exact DNS query for a listed campaign payload hostname is a sighting, even without an answer (Suricata SID `1004805`). Zeek separately reports when the same client establishes TCP on any port to an IPv4 address returned in a matching A answer, within its TTL and a five-minute state cap. This is address contact, not proof that the hostname was used or a payload was downloaded.

- [local-http.zeek](local-http.zeek): three notices. Detect an ARTEX replay-nonce request header, correlate a reported CyberStrikeAI header pair within one request without logging token values, and flag an external client using three or more recognized client families across at least 20 requests to one local server in one minute.
- [local-http.rules](local-http.rules): Suricata SIDs `1004801` and `1004802` match the replay header and a reported placeholder object as a final path component, not a mention in a query string.
- [local-sni.rules](local-sni.rules): SIDs `1004803` and `1004804` match exact reported infrastructure names in visible TLS SNI. Historical infrastructure matches are context, not blocking recommendations.

## Offline replay

For DNS-to-TCP correlation, the sensor must see client-side DNS and the subsequent TCP handshake with the same client address on the same Zeek worker. Resolver-only or encrypted DNS, cached responses not seen by the sensor, IPv6 answers, and CNAME-only matches are not covered. NAT and shared hosting can make the association ambiguous. No HTTP decoding or TLS decryption is needed for this correlation.

With Zeek, Suricata (EVE alert logging enabled), Ruby, `shasum`, and jq on `PATH`, run from this repository:

```sh
bash validate.sh
```

The runner checks the [original regression capture](tests/local-http.pcap), the [campaign capture](tests/campaign.pcap), and offline hunt controls. No feed download, engine source checkout, or third-party rule pack is required. For an optional independent comparison, run `ruby tests/compare-source.rb /path/to/agentic-attack-detections` against a Git checkout containing the pinned commit.

The standalone replay passed on Zeek 9.1.0-dev.656 and Suricata 9.0.0-dev. This checks the expected matches and controls in the synthetic fixture, not incident attribution or production false-positive rates.

## Research credit

The Zeek scripts, local Suricata signatures, retrospective hunts, and replay tests were written for this repository. The indicator **values and confidence** are not original research: they come from [ThreatDefence's pinned inventory](https://github.com/ThreatDefence/agentic-attack-detections/tree/354e8a309803730b8f01fba1489aa0ea00d38ae6). Their published detections and hunts informed the mappings and thresholds. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).