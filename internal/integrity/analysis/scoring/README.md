# Development scoring and evidence admission

M5-02/03 combines body-free projections from the authenticated Worker assembly.
Version/hash checks prevent incompatible inputs; they do not authenticate an
arbitrary caller's features. No HTTP DTO or public trusted/calibrated boolean is
accepted. The parameters and their exact SHA-256 are exposed for reproducibility.

- Prompt weights: format .30, stable affix .25, neutral refusal .20,
  identity/style .10, trusted-baseline difference .15. The last component is
  unavailable until a real baseline resolver exists; prompt A/B is not a baseline.
- Token and response strengths are copied from the token-risk kernel without
  tuning them to satisfy an acceptance threshold. Its fixed-256 development
  example remains Token 41, not an invented >=60 pass.
- Overall development weights: prompt .40, token .35, response .15,
  protocol/evidence .10. Missing components renormalize available weights and
  reduce completeness/confidence; missing and unobserved are distinct.
- Self-report has no voting weight. Identity/style-only observations are capped
  at 39; a single stable family cannot produce prompt risk >=70.
- Confidence is the product of sample, repeatability, quality, baseline and
  applicability factors, with partial <=59 and uncalibrated <=74. No current
  public entry point can grant A or B. Future release admission requires a
  verified calibration artifact; A additionally requires signed gateway evidence.
- Protocol/evidence risk is diagnostic quality, not proof of provider misconduct.
  No-valid/critically-missing observations produce insufficient evidence (D).
- Benjamini-Hochberg correction accepts a complete bounded hypothesis family;
  untested hypotheses are conservatively p=1. Effect size and significance are
  separate, and significance alone never establishes misconduct or evidence grade.

`go test ./internal/integrity/analysis/scoring -count=3 -cover` passes with 98.0%
statement coverage at this checkpoint. Tests cover real behavior/token kernel
outputs, identity/self-report caps, missing data, malformed bindings, all risk
bands, detached parameters, bounded inputs and FDR. These tests are development
evidence, not held-out algorithm calibration or formal review.
