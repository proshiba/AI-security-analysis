# VenomRAT case 3187d3e3b16a56070801701cb040843b67ee52f3a601be142267fd0ea0d91e3b

- Source: [MalwareBazaar](https://bazaar.abuse.ch/sample/3187d3e3b16a56070801701cb040843b67ee52f3a601be142267fd0ea0d91e3b/)
- Original name: `imagetxt0074751.png` (actual PE/.NET x86)
- Campaign type: `dotnet_encrypted_resource_loader`

## Static behavior

The obfuscated managed loader uses manifest resources, GZip, AES/CryptoStream, reflection/dynamic invocation, and process-memory APIs. Its largest embedded entry is `Vbbtcicza.Properties.Resources.resources/Osddmqvmi`: 332,036 bytes, SHA-256 `56885090885afb11b855bbdd9cc67eb18fb11dea98559951053d1ce69a1b7dd1`, entropy 7.999.

The resource is strongly consistent with encrypted or compressed payload material. The final PE/configuration was not recovered in this pass, so the case has no independently recovered C2. This must not be interpreted as proof that the sample has no C2.

## Detection material

A useful medium-confidence analytic combines image-extension masquerading, a valid CLR PE, a very high-entropy managed resource, AES/GZip use, and process-memory APIs. Any one feature is prone to false positives from commercial protectors and installers.

Bounded Base64, reverse, gzip/zlib, AES-literal, and PE-carving transforms recovered only the submitted outer CLR PE itself; no second payload was produced.
