rule Latrodectus_Legacy_PRNG_Broad_2026 {
  meta:
    description = "Broad reviewed Latrodectus legacy version and PRNG/FNV code structure"
    author = "AI-security-analysis"
    confidence = "medium"
    false_positive = "Software combining the same stack-written version pattern with common FNV/PRNG constants"
  strings:
    $version = { C7 44 ?? ?? ?? ?? ?? ?? C7 44 ?? ?? ?? ?? ?? ?? C7 44 ?? ?? ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 89 }
    $fnv_offset = { C5 9D 1C 81 }
    $fnv_prime = { 93 01 00 01 }
    $prng_xor = { 1D 15 00 00 }
    $prng_add = { 59 2E 00 00 }
  condition:
    uint16(0) == 0x5a4d and $version and
    2 of ($fnv_offset, $fnv_prime, $prng_xor, $prng_add)
}

rule Latrodectus_Legacy_PRNG_Strict_2026 {
  meta:
    description = "Strict reviewed Latrodectus legacy version and PRNG/FNV code structure"
    author = "AI-security-analysis"
    confidence = "high"
    false_positive = "Purpose-built emulators or test fixtures reproducing the same implementation"
  strings:
    $version = { C7 44 ?? ?? ?? ?? ?? ?? C7 44 ?? ?? ?? ?? ?? ?? C7 44 ?? ?? ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 89 }
    $fnv_offset = { C5 9D 1C 81 }
    $fnv_prime = { 93 01 00 01 }
    $prng_xor = { 1D 15 00 00 }
    $prng_add = { 59 2E 00 00 }
  condition:
    uint16(0) == 0x5a4d and $version and
    3 of ($fnv_offset, $fnv_prime, $prng_xor, $prng_add)
}
