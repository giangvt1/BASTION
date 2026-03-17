#!/usr/bin/env python3
"""
Train LSTM Autoencoder for User Behavior Analytics.

This script trains an LSTM autoencoder on historical CloudTrail logs to learn
normal user behavior patterns. The trained model is saved to the cache directory
and used by the Forensic Analyst Tier 1 filter.

Usage:
    python scripts/train_lstm_uba.py --data cloudtrail_logs.json --epochs 50

Requirements:
    - Historical CloudTrail logs (JSON format)
    - At least 1000+ events for meaningful training
    - torch, numpy
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bastion.logger import get_logger
from bastion.models.ml_models import LSTMAnomalyDetector

logger = get_logger(__name__)


def load_cloudtrail_logs(file_path: Path) -> list[dict]:
    """Load CloudTrail logs from JSON file."""
    logger.info("loading_logs", path=str(file_path))
    
    with open(file_path, "r") as f:
        data = json.load(f)
    
    # Handle different JSON formats
    if isinstance(data, dict) and "Records" in data:
        records = data["Records"]
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError("Unexpected JSON format. Expected dict with 'Records' or list.")
    
    logger.info("logs_loaded", count=len(records))
    return records


def create_sequences(
    records: list[dict],
    detector: LSTMAnomalyDetector,
    sequence_length: int = 10,
) -> list[list[list[float]]]:
    """Create sliding window sequences from CloudTrail records."""
    logger.info("creating_sequences", sequence_length=sequence_length)
    
    # Extract features for all records
    features = detector._extract_features(records)
    
    # Create sliding windows
    sequences = []
    for i in range(len(features) - sequence_length + 1):
        seq = features[i : i + sequence_length]
        sequences.append(seq)
    
    logger.info("sequences_created", count=len(sequences))
    return sequences


def train_lstm_autoencoder(
    sequences: list[list[list[float]]],
    detector: LSTMAnomalyDetector,
    epochs: int = 50,
    batch_size: int = 32,
    learning_rate: float = 0.001,
) -> nn.Module:
    """Train LSTM autoencoder on normal behavior sequences."""
    logger.info(
        "training_start",
        sequences=len(sequences),
        epochs=epochs,
        batch_size=batch_size,
    )
    
    # Ensure model is loaded
    detector._lazy_load()
    model = detector._model
    device = detector._device
    
    # Convert sequences to tensor
    X = torch.tensor(sequences, dtype=torch.float32)
    dataset = TensorDataset(X, X)  # Autoencoder: input = target
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    
    # Setup training
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    
    model.train()
    
    for epoch in range(epochs):
        epoch_loss = 0.0
        batch_count = 0
        
        for batch_X, batch_target in dataloader:
            batch_X = batch_X.to(device)
            batch_target = batch_target.to(device)
            
            # Forward pass
            optimizer.zero_grad()
            reconstructed = model(batch_X)
            loss = criterion(reconstructed, batch_target)
            
            # Backward pass
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item()
            batch_count += 1
        
        avg_loss = epoch_loss / batch_count
        
        if (epoch + 1) % 10 == 0:
            logger.info(
                "training_progress",
                epoch=epoch + 1,
                loss=round(avg_loss, 6),
            )
    
    logger.info("training_complete", final_loss=round(avg_loss, 6))
    return model


def save_model(model: nn.Module, output_path: Path):
    """Save trained model to disk."""
    logger.info("saving_model", path=str(output_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), output_path)
    logger.info("model_saved", size_mb=round(output_path.stat().st_size / 1024 / 1024, 2))


def evaluate_model(
    model: nn.Module,
    sequences: list[list[list[float]]],
    device: str,
) -> dict:
    """Evaluate model reconstruction error on validation set."""
    logger.info("evaluating_model", sequences=len(sequences))
    
    X = torch.tensor(sequences, dtype=torch.float32).to(device)
    
    model.eval()
    with torch.no_grad():
        reconstructed = model(X)
        mse = torch.mean((X - reconstructed) ** 2, dim=[1, 2])
    
    mse_values = mse.cpu().numpy()
    
    stats = {
        "mean_mse": float(np.mean(mse_values)),
        "std_mse": float(np.std(mse_values)),
        "min_mse": float(np.min(mse_values)),
        "max_mse": float(np.max(mse_values)),
        "p50_mse": float(np.percentile(mse_values, 50)),
        "p95_mse": float(np.percentile(mse_values, 95)),
        "p99_mse": float(np.percentile(mse_values, 99)),
    }
    
    logger.info("evaluation_complete", **stats)
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Train LSTM Autoencoder for User Behavior Analytics"
    )
    parser.add_argument(
        "--data",
        type=Path,
        required=True,
        help="Path to CloudTrail logs JSON file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path.home() / ".cache" / "bastion" / "models" / "lstm_uba_autoencoder.pth",
        help="Output path for trained model",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=50,
        help="Number of training epochs",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=32,
        help="Training batch size",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=0.001,
        help="Learning rate",
    )
    parser.add_argument(
        "--sequence-length",
        type=int,
        default=10,
        help="Sequence length for sliding window",
    )
    parser.add_argument(
        "--validation-split",
        type=float,
        default=0.2,
        help="Fraction of data to use for validation",
    )
    
    args = parser.parse_args()
    
    # Load data
    records = load_cloudtrail_logs(args.data)
    
    if len(records) < 100:
        logger.error("insufficient_data", count=len(records), minimum=100)
        sys.exit(1)
    
    # Initialize detector
    detector = LSTMAnomalyDetector(sequence_length=args.sequence_length)
    
    # Create sequences
    sequences = create_sequences(records, detector, args.sequence_length)
    
    if len(sequences) < 50:
        logger.error("insufficient_sequences", count=len(sequences), minimum=50)
        sys.exit(1)
    
    # Split train/validation
    split_idx = int(len(sequences) * (1 - args.validation_split))
    train_sequences = sequences[:split_idx]
    val_sequences = sequences[split_idx:]
    
    logger.info(
        "data_split",
        train=len(train_sequences),
        validation=len(val_sequences),
    )
    
    # Train model
    model = train_lstm_autoencoder(
        train_sequences,
        detector,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
    )
    
    # Evaluate on validation set
    val_stats = evaluate_model(model, val_sequences, detector._device)
    
    # Save model
    save_model(model, args.output)
    
    # Print summary
    print("\n" + "=" * 60)
    print("Training Summary")
    print("=" * 60)
    print(f"Training sequences: {len(train_sequences)}")
    print(f"Validation sequences: {len(val_sequences)}")
    print(f"Epochs: {args.epochs}")
    print(f"Validation MSE (mean): {val_stats['mean_mse']:.6f}")
    print(f"Validation MSE (p95): {val_stats['p95_mse']:.6f}")
    print(f"Model saved to: {args.output}")
    print("=" * 60)
    print("\nRecommended anomaly threshold: {:.6f}".format(val_stats['p95_mse'] * 2))
    print("(2x the 95th percentile of validation MSE)")
    print("\nTo use this model, ensure it's in the cache directory:")
    print(f"  {args.output}")


if __name__ == "__main__":
    main()
