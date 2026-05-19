# System Architecture

The system follows a Modular CLI Batch Pipeline architecture.

Pipeline:

```text
Log Collector
→ Parser
→ Normalizer
→ Request Preprocessor
→ Rule-based Detector
→ Feature Extractor
→ AI/NLP Detector
→ Risk Engine
→ Post-processor
→ Exporter / SIEM Integration
```
