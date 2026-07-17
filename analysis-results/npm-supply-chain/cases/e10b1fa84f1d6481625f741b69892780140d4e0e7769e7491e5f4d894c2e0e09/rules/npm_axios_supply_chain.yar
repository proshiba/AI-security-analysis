import "hash"

rule NPM_Plain_Crypto_JS_Setup_Exact {
  meta:
    description = "Exact malicious setup.js from axios/plain-crypto-js compromise"
    confidence = "high"
    false_positive = "low"
  condition:
    hash.sha256(0, filesize) == "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09"
}

rule NPM_Plain_Crypto_JS_Postinstall_Structure {
  meta:
    description = "Distinctive static marker cluster in malicious npm postinstall"
    confidence = "high"
    false_positive = "low; test against internal JavaScript build tools"
  strings:
    $order = "OrDeR_7077" ascii fullword
    $campaign = "6202033" ascii fullword
    $decoder = "_trans_2" ascii
    $xor = "String.fromCharCode(S^a^333)" ascii
  condition:
    filesize < 100KB and all of them
}
