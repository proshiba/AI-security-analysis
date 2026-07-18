import "hash"

rule Trivy_TeamPCP_Release_Artifacts {
  meta:
    description = "Exact official hashes for selected malicious Trivy v0.69.4 release artifacts"
    confidence = "high"
    false_positive = "low"
  condition:
    hash.sha256(0, filesize) == "0376b98064636c30f5fbe60fb3b1225516e23e88dd7e909937f81d9265292e7d" or
    hash.sha256(0, filesize) == "822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0" or
    hash.sha256(0, filesize) == "385d498d18a3a7c67878ca7322716f9da25683eb1a4bf9e9592da0d5f2ab09f6"
}
