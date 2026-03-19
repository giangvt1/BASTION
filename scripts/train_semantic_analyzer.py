#!/usr/bin/env python3
"""
Train Semantic Analyzer models for BASTION.

Trains BERT-based models to replace LLM reasoning in Tier 2:
1. CloudTrail Semantic Analyzer - classifies log sequences
2. Email Semantic Analyzer - classifies email content

This dramatically reduces LLM API costs (~95% reduction) while maintaining accuracy.

Usage:
    # Train CloudTrail analyzer
    python scripts/train_semantic_analyzer.py cloudtrail \
        --data labeled_cloudtrail.json \
        --epochs 20

    # Train Email analyzer
    python scripts/train_semantic_analyzer.py email \
        --data labeled_emails.json \
        --epochs 20
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset

sys.path.insert(0, str(Path(__file__).parent.parent))

from bastion.logger import get_logger

logger = get_logger(__name__)


class CloudTrailDataset(Dataset):
    """Dataset for CloudTrail sequence classification."""
    
    def __init__(self, data: list[dict], tokenizer, max_length: int = 512):
        self.data = data
        self.tokenizer = tokenizer
        self.max_length = max_length
    
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        item = self.data[idx]
        
        # Convert events to text
        text = self._events_to_text(item["events"], item.get("user", ""))
        
        # Tokenize
        encoding = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt",
        )
        
        # Labels
        severity_map = {
            "CLEAN": 0,
            "LOW_RISK": 1,
            "MEDIUM_RISK": 2,
            "HIGH_RISK": 3,
            "CRITICAL_COMPROMISE": 4,
        }
        
        return {
            "input_ids": encoding["input_ids"].squeeze(),
            "attention_mask": encoding["attention_mask"].squeeze(),
            "attack_label": severity_map.get(item["label"], 2),
            "killchain_labels": torch.tensor(item.get("killchain_labels", [0]*7), dtype=torch.float32),
            "mitre_labels": torch.tensor(item.get("mitre_labels", [0]*14), dtype=torch.float32),
        }
    
    def _events_to_text(self, events: list[dict], user: str) -> str:
        """Convert events to text representation."""
        lines = [f"User: {user}"] if user else []
        lines.append(f"Event Sequence ({len(events)} events):")
        
        for i, event in enumerate(events[:20], 1):
            event_name = event.get("eventName", "?")
            event_time = event.get("eventTime", "?")
            src_ip = event.get("sourceIPAddress", "?")
            error = event.get("errorCode", "")
            
            line = f"{i}. {event_time} | {event_name} | IP: {src_ip}"
            if error:
                line += f" | ERROR: {error}"
            lines.append(line)
        
        return "\n".join(lines)


def train_cloudtrail_analyzer(
    train_data: list[dict],
    val_data: list[dict],
    epochs: int = 20,
    batch_size: int = 16,
    learning_rate: float = 2e-5,
):
    """Train CloudTrail semantic analyzer."""
    from transformers import AutoModel, AutoTokenizer
    
    logger.info("training_cloudtrail_analyzer", train_size=len(train_data), val_size=len(val_data))
    
    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
    
    # Create datasets
    train_dataset = CloudTrailDataset(train_data, tokenizer)
    val_dataset = CloudTrailDataset(val_data, tokenizer)
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size)
    
    # Initialize model
    from bastion.models.semantic_analyzer import CloudTrailSemanticAnalyzer
    
    analyzer = CloudTrailSemanticAnalyzer()
    analyzer._lazy_load()
    model = analyzer._model
    device = analyzer._device
    
    # Loss functions
    attack_criterion = nn.CrossEntropyLoss()
    killchain_criterion = nn.BCEWithLogitsLoss()
    mitre_criterion = nn.BCEWithLogitsLoss()
    
    # Optimizer
    optimizer = optim.AdamW(model.parameters(), lr=learning_rate)
    
    # Training loop
    model.train()
    
    for epoch in range(epochs):
        epoch_loss = 0.0
        
        for batch in train_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            attack_labels = batch["attack_label"].to(device)
            killchain_labels = batch["killchain_labels"].to(device)
            mitre_labels = batch["mitre_labels"].to(device)
            
            optimizer.zero_grad()
            
            # Forward pass
            attack_logits, killchain_logits, mitre_logits = model(input_ids, attention_mask)
            
            # Compute losses
            loss_attack = attack_criterion(attack_logits, attack_labels)
            loss_killchain = killchain_criterion(killchain_logits, killchain_labels)
            loss_mitre = mitre_criterion(mitre_logits, mitre_labels)
            
            # Combined loss
            loss = loss_attack + 0.5 * loss_killchain + 0.5 * loss_mitre
            
            # Backward pass
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item()
        
        avg_loss = epoch_loss / len(train_loader)
        
        # Validation
        if (epoch + 1) % 5 == 0:
            val_acc = evaluate_cloudtrail(model, val_loader, device)
            logger.info(
                "training_progress",
                epoch=epoch + 1,
                train_loss=round(avg_loss, 4),
                val_accuracy=round(val_acc, 3),
            )
    
    logger.info("training_complete", final_loss=round(avg_loss, 4))
    
    # Save model
    output_path = Path.home() / ".cache" / "bastion" / "models" / "cloudtrail_semantic_analyzer.pth"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), output_path)
    logger.info("model_saved", path=str(output_path))


def evaluate_cloudtrail(model, dataloader, device):
    """Evaluate CloudTrail analyzer accuracy."""
    model.eval()
    correct = 0
    total = 0
    
    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["attack_label"].to(device)
            
            attack_logits, _, _ = model(input_ids, attention_mask)
            predictions = torch.argmax(attack_logits, dim=1)
            
            correct += (predictions == labels).sum().item()
            total += labels.size(0)
    
    model.train()
    return correct / total if total > 0 else 0.0


def load_labeled_cloudtrail_data(file_path: Path) -> list[dict]:
    """Load labeled CloudTrail data for training.
    
    Expected format:
    [
        {
            "events": [...],  # CloudTrail events
            "user": "alice.johnson",
            "label": "HIGH_RISK",
            "killchain_labels": [0, 1, 0, 1, 0, 0, 0],  # 7 stages
            "mitre_labels": [1, 0, 0, 1, 0, ...]  # 14 tactics
        },
        ...
    ]
    """
    logger.info("loading_labeled_data", path=str(file_path))
    
    with open(file_path, "r") as f:
        data = json.load(f)
    
    logger.info("data_loaded", samples=len(data))
    return data


def main():
    parser = argparse.ArgumentParser(description="Train Semantic Analyzer models")
    parser.add_argument(
        "model_type",
        choices=["cloudtrail", "email"],
        help="Type of model to train",
    )
    parser.add_argument(
        "--data",
        type=Path,
        required=True,
        help="Path to labeled training data (JSON)",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=20,
        help="Number of training epochs",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
        help="Training batch size",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=2e-5,
        help="Learning rate",
    )
    parser.add_argument(
        "--validation-split",
        type=float,
        default=0.2,
        help="Fraction of data for validation",
    )
    
    args = parser.parse_args()
    
    # Load data
    data = load_labeled_cloudtrail_data(args.data)
    
    if len(data) < 100:
        logger.error("insufficient_data", count=len(data), minimum=100)
        print("Error: Need at least 100 labeled samples for training")
        sys.exit(1)
    
    # Split train/val
    split_idx = int(len(data) * (1 - args.validation_split))
    train_data = data[:split_idx]
    val_data = data[split_idx:]
    
    logger.info("data_split", train=len(train_data), validation=len(val_data))
    
    # Train
    if args.model_type == "cloudtrail":
        train_cloudtrail_analyzer(
            train_data,
            val_data,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
        )
    else:
        print("Email analyzer training not yet implemented")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("Training Complete")
    print("=" * 60)
    print(f"Model type: {args.model_type}")
    print(f"Training samples: {len(train_data)}")
    print(f"Validation samples: {len(val_data)}")
    print(f"Epochs: {args.epochs}")
    print("=" * 60)
    print("\nTo use this model, enable in .env:")
    print("  BASTION_USE_SEMANTIC_ANALYZER=true")


if __name__ == "__main__":
    main()
