# Notebooks

This directory contains the Jupyter notebook documenting all AI/ML models used in BASTION.

## `bastion_ml_models.ipynb`

A single, comprehensive notebook covering training, evaluation, and integration of all three custom ML/DL models:

| Part | Model | Architecture | Purpose |
|------|-------|-------------|---------|
| Part 1 | Phishing Email Classifier | Fine-tuned DistilBERT | Tier 1 email triage |
| Part 2 | LSTM Anomaly Detector | LSTM Autoencoder | CloudTrail user behavior anomaly detection |
| Part 3 | Semantic Embedder | Sentence-BERT (all-MiniLM-L6-v2) | RAG vector search (Pinecone) |

## Datasets Used

| Dataset | Location | Records |
|---------|----------|---------|
| CEAS_08 phishing emails | `dataset/mail/CEAS_08.csv` | ~39K |
| CloudTrail logs | `dataset/logs/dec12_18features.csv` | ~1.9M |
| MITRE ATT&CK corpus | `bastion/data/mitre_attack_corpus/` | curated |

## Note

BASTION primarily uses **foundation model orchestration** (Gemini via LangGraph) for reasoning and report generation. The custom ML models above handle specialized classification tasks where **deterministic, low-latency, zero-cost inference** is required. No additional custom model training notebooks are needed beyond this file.
