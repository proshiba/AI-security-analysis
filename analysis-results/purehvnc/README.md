# PureHVNC / PureRAT analysis results

This directory records terminal PureHVNC/PureRAT classification independently
from delivery layers.

| Primary artifact | Variant | Delivery | Configured C2 | Confidence |
|---|---|---|---|---|
| `e5541255...d5633d0` | managed PureRAT 4.4.1 | CHRD/WAV ? Donut ? .NET loader | `tirakian.com:56001`, `:56002`, `:56003` | confirmed static config |

The full terminal payload and protobuf configuration are recoverable from the
submitted DLL without execution or a network download. The former `e8a4?`
result was removed from this directory after the submission reassignment; its
report records the native `10FX` terminal as a secondary finding under the
DonutLoader-assigned case.
