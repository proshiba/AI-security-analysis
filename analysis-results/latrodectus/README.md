# Latrodectus analysis results

This directory separates family configuration, version/group metadata,
delivery shape, and reusable detection hypotheses.

## Reviewed batches

- [VX-Underground batch, 2026-07-16](vx-underground-20260716/README.md):
  54 submissions, 33 validated legacy configurations, 27 unique confirmed C2
  URLs, 8 group names, and versions spanning the reviewed 1.1 through 1.3
  generations.

## Detection material

- [YARA](rules/yara/latrodectus_protocol_2026.yar)
- [Sigma](rules/sigma/latrodectus_rundll32_user_path.yml)

The current extractor covers the reviewed legacy PRNG-encrypted string profile.
AES-CTR generations remain a separate parser profile. No sample, loader, or DLL
was executed, and no endpoint was contacted.
