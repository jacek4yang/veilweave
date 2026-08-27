// A proxyip egress candidate: the IPv4 (or host) + port the relay will dial, plus
// its country for ISP-aware ranking. This subscription deals only in proxyips
// (the egress baked into each signed UUID), so the model is deliberately minimal.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressEntry {
    pub host: String,
    pub port: u16,
    pub country: String,
}
