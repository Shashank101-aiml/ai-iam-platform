"""
AI-IAM Platform Utility helpers.
Provides common helper functions used across services and API routes.
"""

from app.core.security import compute_entry_hash
from app.models.base import generate_uuid

__all__ = ["generate_uuid", "compute_entry_hash"]
