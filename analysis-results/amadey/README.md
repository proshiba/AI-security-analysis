# Amadey analysis results

Reusable static configuration extraction, campaign classification, and detection
material for Amadey are maintained separately from the raw samples.

## Reviewed batches

- [VX-Underground batch, 2026-07-16](vx-underground-20260716/README.md):
  35 submissions, 12 validated static configurations, 7 unique confirmed C2
  URLs, and 11 protected wrappers requiring an inner PE for complete config
  recovery.

## Detection material

- [YARA](rules/yara/amadey_config_behavior_2026.yar)
- [Sigma](rules/sigma/amadey_user_run_persistence.yml)

The extractor validates the reviewed custom-alphabet/Base64 layout before
labeling an endpoint as C2. Literal URLs without that structure remain
candidates. No sample or recovered payload was executed, and no endpoint was
contacted.
