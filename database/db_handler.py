# =============================================================================
# database/db_handler.py — MongoDB Database Handler
# =============================================================================
# Provides a clean abstraction over all MongoDB operations:
#   • Inserting traffic stats and alert records
#   • Querying historical data
#   • Managing TTL indexes for automatic data expiry
#
# Collections:
#   netmon.traffic_stats  — per-interval aggregated metrics
#   netmon.alerts         — anomaly and alert events
#   netmon.connections    — active connection snapshots

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

import config
from utils.logger import get_logger

logger = get_logger(__name__)


class DatabaseHandler:
    """
    Wraps all MongoDB interactions for the Network Monitoring System.
    Uses lazy initialization: the connection is established on first use.
    """

    def __init__(self):
        self._client = None
        self._db     = None
        self._connected = False

    # ─── Connection ───────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """
        Establish a connection to MongoDB and ensure indexes exist.
        Returns True on success, False on failure.
        """
        try:
            from pymongo import MongoClient, ASCENDING, DESCENDING  # type: ignore
            from pymongo.errors import ConnectionFailure             # type: ignore

            self._client = MongoClient(
                config.MONGO_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
            )
            # Force connection to verify the server is reachable
            self._client.admin.command("ping")
            self._db = self._client[config.MONGO_DB_NAME]
            self._connected = True

            self._create_indexes()
            logger.info("MongoDB connected — db=%s", config.MONGO_DB_NAME)
            return True

        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "MongoDB unavailable (%s) — running without persistence", exc
            )
            self._connected = False
            return False

    def disconnect(self) -> None:
        if self._client:
            self._client.close()
            logger.info("MongoDB disconnected")

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ─── Index Setup ──────────────────────────────────────────────────────────

    def _create_indexes(self) -> None:
        """
        Create performance-critical indexes on first run.
        Idempotent — safe to call on every startup.
        """
        from pymongo import ASCENDING, DESCENDING  # type: ignore

        db = self._db

        # traffic_stats: query by time range → timestamp index
        db[config.COL_STATS].create_index(
            [("timestamp", DESCENDING)], background=True
        )

        # alerts: query by time + severity → compound index
        db[config.COL_ALERTS].create_index(
            [("timestamp", DESCENDING), ("severity", ASCENDING)],
            background=True,
        )

        # TTL index: auto-delete traffic_stats older than N days
        db[config.COL_STATS].create_index(
            [("created_at", ASCENDING)],
            expireAfterSeconds=config.PACKET_TTL_DAYS * 86_400,
            background=True,
        )

        logger.debug("MongoDB indexes verified/created")

    # ─── Traffic Stats ────────────────────────────────────────────────────────

    def insert_traffic_stat(self, stat: Dict) -> Optional[str]:
        """
        Persist a single interval's aggregated traffic metrics.

        Args:
            stat: Dict produced by TrafficAnalyzer._compute_stats()

        Returns:
            Inserted document ID string, or None on failure.
        """
        if not self._connected:
            return None
        try:
            doc = dict(stat)
            doc["created_at"] = datetime.now(timezone.utc)  # used by TTL index
            result = self._db[config.COL_STATS].insert_one(doc)
            return str(result.inserted_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("insert_traffic_stat failed: %s", exc)
            return None

    def get_traffic_history(
        self,
        minutes: int = 60,
        limit: int = 200,
    ) -> List[Dict]:
        """
        Retrieve aggregated traffic stats for the past N minutes.

        Args:
            minutes: How far back to query.
            limit:   Maximum documents to return.

        Returns:
            List of stat documents (oldest first), with _id removed.
        """
        if not self._connected:
            return []
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
            cursor = (
                self._db[config.COL_STATS]
                .find({"timestamp": {"$gte": cutoff.isoformat()}})
                .sort("timestamp", 1)
                .limit(limit)
            )
            return [_strip_id(doc) for doc in cursor]
        except Exception as exc:  # noqa: BLE001
            logger.error("get_traffic_history failed: %s", exc)
            return []

    # ─── Alerts ───────────────────────────────────────────────────────────────

    def insert_alert(self, alert: Dict) -> Optional[str]:
        """
        Persist an anomaly alert event.

        Alert schema:
          {
            "type":       str,   # e.g. "TRAFFIC_SPIKE"
            "severity":   str,   # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
            "source_ip":  str | None,
            "message":    str,
            "details":    dict,
            "timestamp":  str,
          }
        """
        if not self._connected:
            return None
        try:
            doc = dict(alert)
            doc["created_at"] = datetime.now(timezone.utc)
            result = self._db[config.COL_ALERTS].insert_one(doc)
            return str(result.inserted_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("insert_alert failed: %s", exc)
            return None

    def get_alerts(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        minutes: Optional[int] = None,
    ) -> List[Dict]:
        """
        Query alerts with optional filters.

        Args:
            limit:    Max alerts to return.
            severity: Filter to a specific severity level.
            minutes:  Return only alerts from the past N minutes.
        """
        if not self._connected:
            return []
        try:
            query: Dict[str, Any] = {}
            if severity:
                query["severity"] = severity.upper()
            if minutes:
                cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
                query["timestamp"] = {"$gte": cutoff.isoformat()}

            cursor = (
                self._db[config.COL_ALERTS]
                .find(query)
                .sort("timestamp", -1)
                .limit(limit)
            )
            return [_strip_id(doc) for doc in cursor]
        except Exception as exc:  # noqa: BLE001
            logger.error("get_alerts failed: %s", exc)
            return []

    def get_alert_count(self, minutes: int = 60) -> int:
        """Return the number of alerts in the past N minutes."""
        if not self._connected:
            return 0
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
            return self._db[config.COL_ALERTS].count_documents(
                {"timestamp": {"$gte": cutoff.isoformat()}}
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("get_alert_count failed: %s", exc)
            return 0

    # ─── Connections ──────────────────────────────────────────────────────────

    def update_connections(self, connections: List[Dict]) -> None:
        """
        Replace the current active-connections snapshot.
        Drops the old collection and inserts the new snapshot — simple and fast.
        """
        if not self._connected or not connections:
            return
        try:
            col = self._db[config.COL_CONNECTIONS]
            col.drop()
            if connections:
                col.insert_many(connections)
        except Exception as exc:  # noqa: BLE001
            logger.error("update_connections failed: %s", exc)

    def get_connections(self, limit: int = 50) -> List[Dict]:
        """Return the latest active connections snapshot."""
        if not self._connected:
            return []
        try:
            return [
                _strip_id(doc)
                for doc in self._db[config.COL_CONNECTIONS].find().limit(limit)
            ]
        except Exception as exc:  # noqa: BLE001
            logger.error("get_connections failed: %s", exc)
            return []

    # ─── Raw Packets (optional) ───────────────────────────────────────────────

    def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        """Fetch the most recent raw packet summaries for export."""
        if not self._connected:
            return []
        try:
            cursor = (
                self._db[config.COL_STATS]
                .find()
                .sort("timestamp", -1)
                .limit(limit)
            )
            return [_strip_id(doc) for doc in cursor]
        except Exception as exc:  # noqa: BLE001
            logger.error("get_recent_packets failed: %s", exc)
            return []


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _strip_id(doc: Dict) -> Dict:
    """Remove MongoDB's ObjectId '_id' field (not JSON-serializable)."""
    doc.pop("_id", None)
    doc.pop("created_at", None)
    return doc
