# ARTEX-NSM

ARTEX-NSM is a standalone set of network detections for Zeek and Suricata. It correlates HTTP client behavior and identifies specific request artifacts and TLS server names reported in agentic attack campaigns. A match describes what the sensor saw; it does not establish which tool or operator sent the traffic.

- [local-http.zeek](local-http.zeek): three notices. Detect an ARTEX replay-nonce request header, correlate a reported CyberStrikeAI header pair within one request without logging token values, and flag an external client using three or more recognized client families across at least 20 requests to one local server in one minute.
- [local-http.rules](local-http.rules): Suricata SIDs `1004801` and `1004802` match the replay header and a reported placeholder object as a final path component, not a mention in a query string.
- [local-sni.rules](local-sni.rules): SIDs `1004803` and `1004804` match exact reported infrastructure names in visible TLS SNI. Historical infrastructure matches are context, not blocking recommendations.

## Offline replay

With Zeek, Suricata (EVE alert logging enabled), and jq on `PATH`, run from this repository:

```sh
bash validate.sh
```

The runner loads only the detection files above and checks exact notice types, signature IDs, and source addresses against the [synthetic capture](tests/local-http.pcap), including near misses and below-threshold traffic. No feed download, engine source checkout, or third-party rule pack is required. For deployment, set Zeek's local networks for your site and check Suricata SID availability.

The standalone replay passed on Zeek 9.1.0-dev.656 and Suricata 9.0.0-dev. This checks the expected matches and controls in the synthetic fixture, not incident attribution or production false-positive rates.

## Research credit

Thanks to [ThreatDefence's agentic-attack-detections project](https://github.com/ThreatDefence/agentic-attack-detections) for documenting campaign indicators and hunting behaviors that informed this work, including the ARTEX replay-nonce header and user-agent family burst. The Zeek scripts, Suricata signatures, and synthetic replay tests in ARTEX-NSM were written for this repository.