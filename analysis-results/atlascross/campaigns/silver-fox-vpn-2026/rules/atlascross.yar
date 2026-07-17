import "hash"

rule AtlasCross_Reviewed_Artifacts {
  meta:
    description = "Reviewed AtlasCross loader, shellcode, RAT or config"
    confidence = "high"
    false_positive = "low"
  condition:
    hash.sha256(0, filesize) == "fa5d3a9eebf9310148e7b980fefa7bc3f3a8e8ee7a8d0bd21a057c54c5a47560" or
    hash.sha256(0, filesize) == "8cecb015075094fe42d613a371480ba5f5813c931eb48eb7b893dac835172b37" or
    hash.sha256(0, filesize) == "8009908c6c76a72e20e4020a9f9eb9e4d4203507f67a624ecf7f4ed672cf4b68"
}

rule AtlasCross_Static_Marker_Cluster {
  meta:
    description = "Atlas RAT protocol, export and configuration marker cluster"
    confidence = "medium-high"
    false_positive = "low when two or more markers coexist"
  strings:
    $beacon = { 53 46 75 63 6B 00 00 00 }
    $export = "AtlasInfo" ascii
    $ini = "AtlasPro.ini" ascii wide
    $marker = "By@V<" ascii
    $mutex = "K8A9C1D9-FUCK-AE99-CLOSE" ascii wide
  condition:
    2 of them
}
