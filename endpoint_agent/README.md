# ShieldDome Endpoint Agent

This directory contains the design and, later, the implementation of the standalone Windows Endpoint Agent. The existing ShieldDome API, Worker, web console, database, and browser extension remain unchanged.

## Product Definition

ShieldDome Endpoint Agent is a per-Windows-user, offline phishing-email detection application.

- Windows 10/11 x64, four CPU cores, 8 GB RAM minimum.
- No discrete GPU requirement.
- Local Mail Risk Model package no larger than 2 GB.
- Agent steady-state memory no larger than 1.5 GB; detection peak no larger than 2.5 GB.
- Rule detection target below 300 ms; model inference target below 3 seconds.
- The Agent never calls a central backend, external model, reputation service, telemetry endpoint, or background updater.
- One Unified Model Release is trained by the company and distributed inside a complete Endpoint Release.
- Endpoint Agents perform inference only. They never retrain from user email.
- Original email and attachment content are not persisted.
- Encrypted Endpoint Evidence Records are retained for 15 days.
- Browser UI displays only risk level, execution state, generic advice, and a local event ID.
- Protection Mode warns and requests confirmation for strongly evidenced high-risk actions, but never deletes, quarantines, or moves email.

## Target Architecture

```mermaid
flowchart LR
    Browser[Browser extension] -->|Native Messaging| Intake[Mail Intake module]
    EML[EML import] --> Intake
    Future[Future mail-client adapter] --> Intake

    Intake --> Kernel[Detection Kernel module]
    Kernel --> Parser[Existing ShieldDome parsing and rules]
    Kernel --> Features[Feature Pipeline module]
    Features --> Inference[Local Inference module]
    Kernel --> Fusion[Risk Fusion module]
    Inference --> Fusion
    Examples[Confirmed Example Library] --> Fusion
    Fusion --> Projection[Result Projection module]
    Fusion --> Evidence[Local Evidence Store]

    Projection --> Browser
    Projection --> Console[Tray application and personal console]
    Evidence --> Dashboard[Personal Security Dashboard]
```

The Detection Kernel is the top-level deep module. Callers cross one interface and do not need to understand parsing, model runtime, evidence weights, abstention, storage, or result projection.

## Deep Modules

### Detection Kernel

Interface:

```text
analyze(mail_observation) -> detection_outcome
```

Implementation hides parsing, feature extraction, rule analysis, model inference, similarity calibration, failure degradation, risk fusion, evidence persistence, and result projection.

### Mail Intake

All intake adapters produce the same normalized `MailObservation`.

- Initial adapter: Chrome/Edge Native Messaging.
- Second adapter: manual or Windows-shell `.eml` import.
- Later adapters: official integrations for Outlook, Foxmail, QQ Mail, or other clients where a supported extension mechanism exists.

Mail Intake never reads proprietary mailbox databases, intercepts network traffic, injects client processes, or bypasses client access controls.

### Feature Pipeline

Training and endpoint inference must cross the same seam and use the same feature-schema version.

Feature families:

- SPF, DKIM, DMARC and authentication availability.
- Sender and reply-to consistency.
- Root-domain, subdomain, Unicode, punycode and display-address properties.
- URL count, visible-target mismatch, redirects, IP literals, suspicious ports and lexical properties.
- Subject/body length and limited sanitized text representation.
- Credential, payment, urgency and impersonation intent indicators.
- Attachment Metadata Assessment only: name, declared type, size and dangerous extension properties.
- Existing deterministic rule IDs and protective evidence.

### Local Inference

The first production adapter uses ONNX Runtime on CPU. A deterministic fake adapter supports tests.

Output is a `ModelAssessment` containing:

- phishing probability;
- confident-benign, uncertain, or confident-phishing state;
- model and feature-schema versions;
- inference duration;
- completed, unavailable, incompatible, or failed status.

The model never returns natural-language reasons or a final risk level.

### Risk Fusion

Risk Fusion combines deterministic evidence, Model Assessment, and bounded similarity evidence from the Confirmed Example Library.

- Model-only evidence cannot create a critical result.
- Uncertain model output adds no strong risk evidence.
- Similar benign examples have a bounded protective effect.
- Similar phishing examples have a bounded risk effect.
- Strong authentication, blacklist, URL and attachment-metadata evidence cannot be cancelled by similarity.
- Model failure always degrades to deterministic rules.

### Local Evidence Store

- Per-user storage under `%LOCALAPPDATA%`.
- Encryption key protected with Windows DPAPI.
- AES-GCM encrypted structured records.
- No original `.eml`, full body, attachment content, credentials, tokens, or full recipient lists.
- Automatic deletion after 15 days.
- No network upload.
- Explicit user action is required to export a sanitized diagnostic package.

### Confirmed Example Library

The library stores only sanitized features, vectors, labels and hashes for user-confirmed examples. It calibrates similar future email with bounded evidence and never changes model weights.

### Endpoint Release

- One complete installer contains Agent, browser extension, Unified Model Release and policy.
- Models are not hot-updated independently.
- Startup verifies a release manifest and model SHA-256.
- Installation directories are not writable by ordinary users.
- The previous complete release is retained for rollback.
- Unsupported or damaged models cause rule-only degradation.

## Model Development

### Model Shape

Use a license-approved Chinese/English pretrained text encoder plus ShieldDome-owned feature extraction, classification, calibration and risk fusion.

Recommended progression:

1. Structured-feature baseline using logistic regression or gradient-boosted trees.
2. Frozen multilingual text embeddings combined with structured features.
3. Fine-tune the encoder only after the Approved Training Corpus is large and diverse enough.
4. Export the chosen model to ONNX and apply validated quantization.

The target is approximately 500 MB, not the 2 GB maximum. The maximum exists as a release guardrail.

### Approved Training Corpus

- License-compatible public benign and phishing email datasets.
- ShieldDome simulated phishing and benign enterprise templates.
- Human-confirmed phishing cases.
- No unreviewed personal inbox email.
- RAG or feedback records are candidates only; they require review before inclusion.
- Every candidate must carry non-sensitive label-guideline, label-evidence, reviewer, source-dataset and source-evidence identifiers.
- Authorization must be approved or active, unexpired at admission, and separately allow internal training and endpoint model-weight distribution.
- Privacy review must be approved and bind a sanitization-policy version, privacy-evidence digest and sanitized-representation digest.
- Deduplicate by raw hash, normalized hash and template/near-duplicate clustering.
- Split by source, campaign/template and time to prevent leakage.
- Keep immutable dataset, corpus and feature-schema versions plus a deterministic manifest digest for every model release.

`CorpusGovernance.prepare` is the only admission seam for these facts. Missing, unsafe or inconsistent governance metadata is rejected with a stable code; rejected values are never copied into the rejection record. This hardening does not create an Approved Training Corpus and does not start Phase 3 model work.

### Release Gates

- Phishing recall at least 95%.
- Benign false-positive rate no more than 1%.
- High-confidence phishing precision at least 90%.
- Abstention rate no more than 25%.
- Report Chinese, English and mixed-language results separately.
- Report browser, EML and public-source results separately.
- Lowest supported hardware inference below 3 seconds.
- Rule-only degradation passes for timeout, memory pressure, corruption and incompatibility.
- No key metric may regress from the currently released model without explicit approval.

## Local User Experience

### Browser

- Risk level: low, medium, high or critical.
- State: complete, uncertain, degraded or unavailable.
- Generic action: continue, verify sender, avoid credentials, or contact security staff.
- Local event ID.
- No model reason, internal rule detail, RAG content, model name or policy weight.

### Tray And Personal Console

- Agent and model status.
- Drag-and-drop `.eml` detection.
- Today's detection count.
- Fifteen-day detection trend.
- Risk distribution and intake-source distribution.
- Model abstention and degradation counts.
- Local 15-day evidence history.
- Confirmed Example Library management.
- False-positive and missed-phishing feedback.
- Sanitized diagnostic export and local-data deletion.

## Attachment Safety

The first release performs Attachment Metadata Assessment only.

- Do not download attachments automatically.
- Do not open, preview, extract or execute attachments.
- Do not invoke Office, PDF readers, shell handlers or system preview.
- Identify suspicious names, double extensions, dangerous declared types, sizes and encrypted-archive indicators already exposed by the mail client.

A future isolated attachment-inspection process must be designed and security-reviewed separately. It must never run inside the Agent process.

## Proposed Directory Layout

```text
endpoint_agent/
  README.md
  pyproject.toml
  src/shielddome_endpoint/
    app.py
    intake/
      native_host.py
      eml_import.py
      normalized_mail.py
    detection/
      kernel.py
      feature_pipeline.py
      local_inference.py
      risk_fusion.py
      result_projection.py
      attachment_metadata.py
    storage/
      evidence_store.py
      example_library.py
      crypto.py
      retention.py
    release/
      manifest.py
      integrity.py
      compatibility.py
    ui/
      tray.py
      dashboard.py
  extension/
  training/
    dataset.py
    train_baseline.py
    train_encoder.py
    evaluate.py
    export_onnx.py
  models/
    README.md
  policies/
  packaging/
  tests/
```

Model binaries, training corpora, raw email, local databases, keys and exported diagnostics must remain outside Git.

## Delivery Plan

1. **Foundation**: independent package, normalized mail types, Feature Pipeline and deterministic baseline tests.
2. **Training corpus**: import, licensing metadata, labeling, deduplication, grouping and dataset snapshots.
3. **Baseline model**: structured classifier, calibration, abstention and source/time-split evaluation.
4. **Text model**: approved encoder benchmarking, ONNX export, quantization and hardware profiling.
5. **Detection Kernel**: local inference, risk fusion, result projection and rule-only degradation.
6. **Browser intake**: new MV3 extension and Native Messaging host without HTTP or tokens.
7. **Local storage and UI**: encrypted 15-day evidence, Confirmed Example Library, tray and dashboard.
8. **Endpoint Release**: installer, integrity checks, ACLs, rollback and clean uninstall.
9. **Security validation**: malformed messages, malicious model files, resource exhaustion, Native Messaging abuse and privacy checks.
10. **Expansion**: `.eml` shell integration, then supported mail-client adapters; isolated attachment inspection remains a separate project.

## Non-Goals For The First Release

- Central backend connectivity or cross-user dashboards.
- External LLM, embedding, reputation or telemetry calls.
- Endpoint model training or personalization.
- Automatic email quarantine or deletion.
- Attachment download, extraction, preview or execution.
- Reading proprietary mail-client databases or intercepting mail traffic.
