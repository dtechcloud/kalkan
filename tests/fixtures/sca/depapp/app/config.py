"""Configuration loader of the kalkan depapp fixture. Never deploy."""

import yaml

DEFAULTS = {"debug": False, "upload_dir": "uploads"}


def merge_defaults(values):
    merged = dict(DEFAULTS)
    merged.update(values or {})
    return merged


def load_uploaded_config(stream):
    return yaml.load(stream)
