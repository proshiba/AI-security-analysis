# PureHVNC / PureRAT analysis results

This directory separates native PureHVNC-like `10FX` agents from managed
PureRAT agents while retaining the shared family relationship. Delivery-layer
names do not replace the terminal family: the DonutLoader case is stored under
`analysis-results/donutloader`, with its terminal payload and C2 summarized here
by reference.

| Primary artifact | Variant | Configured C2 | Confidence |
|---|---|---|---|
| `e8a4f202...ad17ea37` | native `10FX` | `154.82.93.206:8080` | high, static config/call-site |
| `c1a2b48d...0342ffe8` | managed PureRAT 4.4.1 | `tirakian.com:56001-56003` | confirmed, decoded protobuf |

No sample or recovered payload was executed. No C2 was contacted.
