"""Utility modules."""

from __future__ import annotations
import os
from typing import Optional


def resolve_api_key(api_key: Optional[str] = None) -> Optional[str]:
    """Resolve Anthropic API key from argument, env var, or file.

    Search order:
    1. Explicit argument
    2. ANTHROPIC_API_KEY environment variable
    3. ~/.secrets/anthropic_api_key.txt
    4. ~/.anthropic/api_key
    """
    if api_key:
        return api_key
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    for path in (
        os.path.expanduser("~/.secrets/anthropic_api_key.txt"),
        os.path.expanduser("~/.anthropic/api_key"),
    ):
        try:
            with open(path) as f:
                found = f.read().strip()
            if found:
                return found
        except FileNotFoundError:
            continue
    return None
