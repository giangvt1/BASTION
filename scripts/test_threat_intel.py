"""
Test runner for Threat Intel Agent.

Runs unit and integration tests for the Threat Intel agent.
"""

import sys
from pathlib import Path

# Ensure bastion package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest


def main():
    """Run Threat Intel tests."""
    print("\n" + "=" * 70)
    print("  BASTION -- Threat Intel Agent Tests")
    print("=" * 70 + "\n")

    # Run unit tests
    print("Running Unit Tests...")
    print("-" * 70)
    exit_code_unit = pytest.main([
        "tests/unit/test_threat_intel_tier1.py",
        "tests/unit/test_threat_intel_tools.py",
        "-v",
        "--tb=short",
    ])

    # Run integration tests
    print("\n\nRunning Integration Tests...")
    print("-" * 70)
    exit_code_integration = pytest.main([
        "tests/integration/test_threat_intel_node.py",
        "-v",
        "--tb=short",
    ])

    # Summary
    print("\n" + "=" * 70)
    print("  TEST SUMMARY")
    print("=" * 70)
    print(f"  Unit Tests:        {'PASSED' if exit_code_unit == 0 else 'FAILED'}")
    print(f"  Integration Tests: {'PASSED' if exit_code_integration == 0 else 'FAILED'}")
    print()

    return max(exit_code_unit, exit_code_integration)


if __name__ == "__main__":
    sys.exit(main())
