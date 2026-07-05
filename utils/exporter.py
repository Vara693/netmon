# =============================================================================
# utils/exporter.py — CSV and JSON Data Exporter
# =============================================================================
# Allows operators to download captured traffic data for offline analysis.

import csv
import json
import os
from datetime import datetime
from typing import List, Dict, Any

import config
from utils.logger import get_logger

logger = get_logger(__name__)


def _ensure_export_dir() -> str:
    """Create the exports directory if it doesn't exist and return its path."""
    os.makedirs(config.EXPORT_DIR, exist_ok=True)
    return config.EXPORT_DIR


def _timestamp_suffix() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


# ─── CSV Export ───────────────────────────────────────────────────────────────

def export_packets_csv(records: List[Dict[str, Any]]) -> str:
    """
    Write a list of packet-summary dicts to a timestamped CSV file.

    Args:
        records: List of packet documents from MongoDB.

    Returns:
        Absolute path to the written CSV file.
    """
    if not records:
        logger.warning("export_packets_csv called with empty records list")
        return ""

    export_dir = _ensure_export_dir()
    filename   = f"packets_{_timestamp_suffix()}.csv"
    filepath   = os.path.join(export_dir, filename)

    # Flatten keys: exclude MongoDB's internal '_id' field
    fieldnames = [k for k in records[0].keys() if k != "_id"]

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)
        logger.info("Exported %d packet records → %s", len(records), filepath)
        return filepath
    except OSError as exc:
        logger.error("CSV export failed: %s", exc)
        return ""


def export_alerts_csv(alerts: List[Dict[str, Any]]) -> str:
    """Write alert records to a timestamped CSV file."""
    if not alerts:
        return ""

    export_dir = _ensure_export_dir()
    filename   = f"alerts_{_timestamp_suffix()}.csv"
    filepath   = os.path.join(export_dir, filename)
    fieldnames = [k for k in alerts[0].keys() if k != "_id"]

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(alerts)
        logger.info("Exported %d alert records → %s", len(alerts), filepath)
        return filepath
    except OSError as exc:
        logger.error("Alert CSV export failed: %s", exc)
        return ""


# ─── JSON Export ──────────────────────────────────────────────────────────────

def export_json(data: Any, label: str = "export") -> str:
    """
    Serialize arbitrary data to a timestamped JSON file.

    Args:
        data:  Any JSON-serializable Python object.
        label: Prefix for the output filename (e.g., "traffic_stats").

    Returns:
        Absolute path to the written JSON file.
    """
    export_dir = _ensure_export_dir()
    filename   = f"{label}_{_timestamp_suffix()}.json"
    filepath   = os.path.join(export_dir, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        logger.info("Exported JSON → %s", filepath)
        return filepath
    except (OSError, TypeError) as exc:
        logger.error("JSON export failed: %s", exc)
        return ""


# ─── Convenience: in-memory CSV string (for HTTP streaming) ──────────────────

def records_to_csv_string(records: List[Dict[str, Any]]) -> str:
    """
    Convert records to a CSV-formatted string without writing to disk.
    Useful for streaming the response directly from the Flask API.
    """
    import io
    if not records:
        return ""

    output    = io.StringIO()
    fieldnames = [k for k in records[0].keys() if k != "_id"]
    writer    = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(records)
    return output.getvalue()
