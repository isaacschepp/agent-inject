# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Platform-specific directory resolution (XDG-compliant).

Uses ``platformdirs`` so config, data, and cache land in the right place
on Linux, macOS, and Windows without hard-coding paths.
"""

from __future__ import annotations

from pathlib import Path

from platformdirs import user_cache_dir, user_config_dir, user_data_dir

_APP_NAME = "agent-inject"


def config_dir(*, ensure_exists: bool = False) -> Path:
    """Return the user config directory for agent-inject.

    Linux:   ``~/.config/agent-inject/``
    macOS:   ``~/Library/Application Support/agent-inject/``
    Windows: ``%APPDATA%/agent-inject/``
    """
    return Path(user_config_dir(_APP_NAME, ensure_exists=ensure_exists))


def data_dir(*, ensure_exists: bool = False) -> Path:
    """Return the user data directory for agent-inject."""
    return Path(user_data_dir(_APP_NAME, ensure_exists=ensure_exists))


def cache_dir(*, ensure_exists: bool = False) -> Path:
    """Return the user cache directory for agent-inject."""
    return Path(user_cache_dir(_APP_NAME, ensure_exists=ensure_exists))


def config_file() -> Path:
    """Return the default config file path (TOML).

    Does **not** create the file or its parent directory.
    """
    return config_dir() / "config.toml"
