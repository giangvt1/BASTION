"""
Machine Learning models for BASTION threat detection.

This module provides ML-based classifiers and embedders that enhance
the rule-based Tier 1 filters with learned patterns.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import numpy as np

from bastion.logger import get_logger

logger = get_logger(__name__)

# ── Model cache directory ────────────────────────────────────────────────
_MODEL_CACHE_DIR = Path.home() / ".cache" / "bastion" / "models"
_MODEL_CACHE_DIR.mkdir(parents=True, exist_ok=True)


class PhishingClassifier:
    """
    BERT-based phishing email classifier.
    
    Uses a fine-tuned DistilBERT model to classify emails as phishing or legitimate.
    Provides better accuracy than regex-based rules and reduces false positives.
    
    Model: ealvaradob/bert-finetuned-phishing (HuggingFace)
    Accuracy: ~95% on benchmark phishing datasets
    Inference time: ~50-100ms on CPU
    """
    
    def __init__(self, model_name: str = "ealvaradob/bert-finetuned-phishing"):
        self.model_name = model_name
        self._model = None
        self._tokenizer = None
        self._device = None
    
    def _lazy_load(self):
        """Lazy load model to avoid cold start overhead."""
        if self._model is not None:
            return
        
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            
            logger.info("phishing_classifier.loading", model=self.model_name)
            
            self._device = "cuda" if torch.cuda.is_available() else "cpu"
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                cache_dir=str(_MODEL_CACHE_DIR),
            )
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name,
                cache_dir=str(_MODEL_CACHE_DIR),
            )
            self._model.to(self._device)
            self._model.eval()
            
            logger.info(
                "phishing_classifier.loaded",
                model=self.model_name,
                device=self._device,
            )
        except ImportError:
            logger.error(
                "phishing_classifier.import_error",
                message="transformers or torch not installed. Install with: pip install transformers torch",
            )
            raise
        except Exception:
            logger.exception("phishing_classifier.load_error")
            raise
    
    def predict(
        self,
        subject: str,
        body: str,
        threshold: float = 0.7,
    ) -> tuple[float, str]:
        """
        Classify an email as phishing or legitimate.
        
        Args:
            subject: Email subject line
            body: Email body text
            threshold: Classification threshold (default 0.7)
        
        Returns:
            Tuple of (phishing_probability, verdict)
            - phishing_probability: 0.0 to 1.0
            - verdict: "PHISHING" | "SUSPICIOUS" | "CLEAN"
        """
        self._lazy_load()
        
        import torch
        
        # Combine subject and body with [SEP] token
        text = f"{subject} [SEP] {body[:512]}"
        
        try:
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )
            inputs = {k: v.to(self._device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self._model(**inputs)
                probs = torch.softmax(outputs.logits, dim=1)
                phishing_prob = probs[0][1].item()
            
            # Determine verdict based on threshold
            if phishing_prob >= threshold:
                verdict = "PHISHING"
            elif phishing_prob >= 0.4:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"
            
            logger.debug(
                "phishing_classifier.prediction",
                score=round(phishing_prob, 3),
                verdict=verdict,
            )
            
            return phishing_prob, verdict
        
        except Exception:
            logger.exception("phishing_classifier.prediction_error")
            # Fallback to SUSPICIOUS on error
            return 0.5, "SUSPICIOUS"


class SemanticEmbedder:
    """
    Sentence-BERT embedder for semantic similarity search.
    
    Replaces deterministic hash-based embeddings with learned semantic
    representations. Dramatically improves vector search quality in Pinecone.
    
    Model: all-MiniLM-L6-v2 (sentence-transformers)
    Dimensions: 384
    Performance: ~50ms per embedding on CPU
    """
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model = None
    
    def _lazy_load(self):
        """Lazy load model to avoid cold start overhead."""
        if self._model is not None:
            return
        
        try:
            from sentence_transformers import SentenceTransformer
            
            logger.info("semantic_embedder.loading", model=self.model_name)
            
            self._model = SentenceTransformer(
                self.model_name,
                cache_folder=str(_MODEL_CACHE_DIR),
            )
            
            logger.info("semantic_embedder.loaded", model=self.model_name)
        except ImportError:
            logger.error(
                "semantic_embedder.import_error",
                message="sentence-transformers not installed. Install with: pip install sentence-transformers",
            )
            raise
        except Exception:
            logger.exception("semantic_embedder.load_error")
            raise
    
    def get_text_embedding(self, text: str) -> list[float]:
        """
        Generate semantic embedding for text.
        
        Args:
            text: Input text to embed
        
        Returns:
            384-dimensional normalized embedding vector
        """
        self._lazy_load()
        
        try:
            embedding = self._model.encode(
                text,
                convert_to_numpy=True,
                normalize_embeddings=True,
            )
            return embedding.tolist()
        except Exception:
            logger.exception("semantic_embedder.embedding_error")
            # Fallback to zero vector
            return [0.0] * 384
    
    def get_email_embedding(self, subject: str, body: str) -> list[float]:
        """
        Generate semantic embedding for an email.
        
        Args:
            subject: Email subject line
            body: Email body text (truncated to 512 chars)
        
        Returns:
            384-dimensional normalized embedding vector
        """
        combined = f"{subject or ''} {body[:512] or ''}"
        return self.get_text_embedding(combined)


# ── Global instances (lazy-loaded) ───────────────────────────────────────

_phishing_classifier: Optional[PhishingClassifier] = None
_semantic_embedder: Optional[SemanticEmbedder] = None


def get_phishing_classifier() -> PhishingClassifier:
    """Get the global PhishingClassifier instance (singleton)."""
    global _phishing_classifier
    if _phishing_classifier is None:
        _phishing_classifier = PhishingClassifier()
    return _phishing_classifier


def get_semantic_embedder() -> SemanticEmbedder:
    """Get the global SemanticEmbedder instance (singleton)."""
    global _semantic_embedder
    if _semantic_embedder is None:
        _semantic_embedder = SemanticEmbedder()
    return _semantic_embedder


class LSTMAnomalyDetector:
    """
    LSTM Autoencoder for User Behavior Analytics (UBA).
    
    Learns baseline behavior patterns for each user and detects anomalies
    in CloudTrail event sequences. Complements Isolation Forest by capturing
    temporal patterns and user-specific baselines.
    
    Architecture:
    - Encoder LSTM: Compresses event sequence into latent representation
    - Decoder LSTM: Reconstructs original sequence
    - Anomaly score: Reconstruction error (MSE)
    
    Features per event:
    - hour_of_day (0-24)
    - day_of_week (0-6)
    - is_high_risk_api (0/1)
    - is_recon_api (0/1)
    - is_data_access (0/1)
    - has_error (0/1)
    - source_ip_entropy (0-1)
    - event_name_hash (0-1, normalized)
    """
    
    def __init__(
        self,
        input_dim: int = 8,
        hidden_dim: int = 32,
        num_layers: int = 2,
        sequence_length: int = 10,
    ):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.sequence_length = sequence_length
        self._model = None
        self._device = None
    
    def _lazy_load(self):
        """Lazy load model to avoid cold start overhead."""
        if self._model is not None:
            return
        
        try:
            import torch
            import torch.nn as nn
            
            logger.info("lstm_detector.loading", hidden_dim=self.hidden_dim)
            
            self._device = "cuda" if torch.cuda.is_available() else "cpu"
            
            # Define LSTM Autoencoder architecture
            class LSTMAutoencoder(nn.Module):
                def __init__(self, input_dim, hidden_dim, num_layers):
                    super().__init__()
                    self.encoder = nn.LSTM(
                        input_dim,
                        hidden_dim,
                        num_layers,
                        batch_first=True,
                    )
                    self.decoder = nn.LSTM(
                        hidden_dim,
                        input_dim,
                        num_layers,
                        batch_first=True,
                    )
                
                def forward(self, x):
                    # Encode
                    _, (hidden, cell) = self.encoder(x)
                    # Decode
                    # Repeat hidden state for each timestep
                    decoder_input = hidden[-1].unsqueeze(1).repeat(1, x.size(1), 1)
                    decoded, _ = self.decoder(decoder_input)
                    return decoded
            
            self._model = LSTMAutoencoder(
                self.input_dim,
                self.hidden_dim,
                self.num_layers,
            )
            
            # Try to load pre-trained weights from cache
            model_path = _MODEL_CACHE_DIR / "lstm_uba_autoencoder.pth"
            if model_path.exists():
                self._model.load_state_dict(
                    torch.load(model_path, map_location=self._device)
                )
                logger.info("lstm_detector.loaded_pretrained", path=str(model_path))
            else:
                logger.info(
                    "lstm_detector.initialized_random",
                    message="No pre-trained weights found. Using random initialization.",
                )
            
            self._model.to(self._device)
            self._model.eval()
            
            logger.info("lstm_detector.loaded", device=self._device)
        except ImportError:
            logger.error(
                "lstm_detector.import_error",
                message="torch not installed. Install with: pip install torch",
            )
            raise
        except Exception:
            logger.exception("lstm_detector.load_error")
            raise
    
    def detect_anomaly(
        self,
        event_sequence: list[dict],
        user: str = "",
    ) -> tuple[float, dict]:
        """
        Detect anomalies in a CloudTrail event sequence.
        
        Args:
            event_sequence: List of CloudTrail event dicts
            user: Username (for logging/context)
        
        Returns:
            Tuple of (anomaly_score, details)
            - anomaly_score: 0.0 to 1.0 (higher = more anomalous)
            - details: Dict with reconstruction_error, threshold, is_anomaly
        """
        self._lazy_load()
        
        import torch
        
        try:
            # Extract features from event sequence
            features = self._extract_features(event_sequence)
            
            if len(features) < 3:
                # Too few events for meaningful analysis
                return 0.0, {
                    "reconstruction_error": 0.0,
                    "threshold": 0.0,
                    "is_anomaly": False,
                    "reason": "insufficient_events",
                }
            
            # Pad or truncate to sequence_length
            if len(features) < self.sequence_length:
                # Pad with zeros
                padding = [[0.0] * self.input_dim] * (self.sequence_length - len(features))
                features = features + padding
            else:
                # Take last N events
                features = features[-self.sequence_length:]
            
            # Convert to tensor
            X = torch.tensor([features], dtype=torch.float32).to(self._device)
            
            # Forward pass
            with torch.no_grad():
                reconstructed = self._model(X)
                mse = torch.mean((X - reconstructed) ** 2).item()
            
            # Normalize MSE to 0-1 range (heuristic threshold)
            # Typical MSE for normal behavior: 0.01-0.05
            # Anomalous behavior: 0.1+
            anomaly_score = min(mse / 0.1, 1.0)
            
            # Threshold for binary classification
            threshold = 0.5
            is_anomaly = anomaly_score >= threshold
            
            logger.debug(
                "lstm_detector.prediction",
                user=user,
                mse=round(mse, 4),
                anomaly_score=round(anomaly_score, 3),
                is_anomaly=is_anomaly,
            )
            
            return anomaly_score, {
                "reconstruction_error": mse,
                "threshold": threshold,
                "is_anomaly": is_anomaly,
                "sequence_length": len(event_sequence),
            }
        
        except Exception:
            logger.exception("lstm_detector.prediction_error", user=user)
            # Fallback to neutral score
            return 0.5, {
                "reconstruction_error": 0.0,
                "threshold": 0.0,
                "is_anomaly": False,
                "reason": "prediction_error",
            }
    
    def _extract_features(self, events: list[dict]) -> list[list[float]]:
        """Extract feature vectors from CloudTrail events."""
        from datetime import datetime
        import hashlib
        
        # Define high-risk and recon APIs
        high_risk_apis = {
            "AssumeRole", "CreateUser", "CreateAccessKey", "AttachUserPolicy",
            "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
            "CreateLoginProfile", "UpdateLoginProfile", "DeleteTrail",
            "StopLogging", "UpdateTrail", "PutEventSelectors",
            "DisableKey", "ScheduleKeyDeletion",
            "AuthorizeSecurityGroupIngress", "CreateSecurityGroup",
            "DeleteFlowLogs", "DeleteBucket", "PutBucketPolicy",
        }
        
        recon_apis = {
            "ListBuckets", "ListUsers", "ListRoles", "ListAccessKeys",
            "DescribeInstances", "DescribeSecurityGroups", "GetBucketAcl",
            "ListAttachedUserPolicies", "ListGroupsForUser",
            "GetAccountAuthorizationDetails",
        }
        
        data_access_apis = {
            "GetObject", "PutObject", "CopyObject", "SelectObjectContent",
        }
        
        features = []
        ip_set = set()
        
        for event in events:
            event_name = event.get("eventName", "")
            event_time_str = event.get("eventTime", "")
            src_ip = event.get("sourceIPAddress", "")
            error_code = event.get("errorCode", "")
            
            # Parse timestamp
            hour = 12.0
            day_of_week = 3.0
            try:
                dt = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
                hour = float(dt.hour + dt.minute / 60)
                day_of_week = float(dt.weekday())
            except (ValueError, AttributeError):
                pass
            
            # Normalize hour and day to 0-1
            hour_norm = hour / 24.0
            day_norm = day_of_week / 7.0
            
            # Binary features
            is_high_risk = 1.0 if event_name in high_risk_apis else 0.0
            is_recon = 1.0 if event_name in recon_apis else 0.0
            is_data_access = 1.0 if event_name in data_access_apis else 0.0
            has_error = 1.0 if error_code else 0.0
            
            # IP entropy (unique IPs seen so far)
            if src_ip:
                ip_set.add(src_ip)
            ip_entropy = min(len(ip_set) / 10.0, 1.0)  # Normalize to 0-1
            
            # Event name hash (deterministic, normalized)
            event_hash = int(hashlib.md5(event_name.encode()).hexdigest()[:8], 16)
            event_hash_norm = (event_hash % 1000) / 1000.0
            
            features.append([
                hour_norm,
                day_norm,
                is_high_risk,
                is_recon,
                is_data_access,
                has_error,
                ip_entropy,
                event_hash_norm,
            ])
        
        return features


# ── Global instances (lazy-loaded) ───────────────────────────────────────

_phishing_classifier: Optional[PhishingClassifier] = None
_semantic_embedder: Optional[SemanticEmbedder] = None
_lstm_detector: Optional[LSTMAnomalyDetector] = None


def get_phishing_classifier() -> PhishingClassifier:
    """Get the global PhishingClassifier instance (singleton)."""
    global _phishing_classifier
    if _phishing_classifier is None:
        _phishing_classifier = PhishingClassifier()
    return _phishing_classifier


def get_semantic_embedder() -> SemanticEmbedder:
    """Get the global SemanticEmbedder instance (singleton)."""
    global _semantic_embedder
    if _semantic_embedder is None:
        _semantic_embedder = SemanticEmbedder()
    return _semantic_embedder


def get_lstm_detector() -> LSTMAnomalyDetector:
    """Get the global LSTMAnomalyDetector instance (singleton)."""
    global _lstm_detector
    if _lstm_detector is None:
        _lstm_detector = LSTMAnomalyDetector()
    return _lstm_detector
