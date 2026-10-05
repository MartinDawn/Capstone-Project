# Limitations of this analysis

## Scope
- Sequential, single-active-transaction cost only. No load, saturation, maximum-throughput, production capacity, availability, or scalability claim follows from these numbers.
- CPU, RAM, storage, packet-level bandwidth, and network capture were not measured.
- Latency covers the first authorization request through access-token issuance. B1 F1 issuance is reported separately and is not part of any repeated-authorization latency.
- Application-level wire bytes are the request plus the response bytes of each named client-facing step. TLS record overhead, retransmission, link-layer framing, and server-to-server traffic are excluded. Request and response bytes are not reported separately.
- B0-C0 and the two B1 configurations use different identity providers and TPP implementations. The architecture-cost and total-change comparisons therefore include implementation differences as well as protocol differences. Only B1-C2 minus B1-C0 changes the cryptographic profile alone.
- Latency depends on the network path between the client machine and the servers.

## Statistics
- Latency statistics use successful attempts only. The failure count and its denominator are shown beside every rate.
- p95 and p99 are labelled descriptive below 100 successful samples or 10 independent blocks.
- A paired-block interval is marked insufficient below 5 valid paired blocks. Intervals from few blocks are unstable even when computed.

## Warnings raised by this analysis
- B0-C0 / Medium: p95 and p99 are descriptive (50 successful samples over 5 block(s))
- B1-C0 / Medium: p95 and p99 are descriptive (50 successful samples over 5 block(s))
- B1-C2 / Medium: p95 and p99 are descriptive (50 successful samples over 5 block(s))
