"""
V6 Layer 0: Chain Synthesizer.

Re-exports V4's chain synthesizer with a unified interface for Layer 0.
"""
from v4.analysis.chain_synthesizer import ChainSynthesizer, AttackChain

__all__ = ["ChainSynthesizer", "AttackChain"]
