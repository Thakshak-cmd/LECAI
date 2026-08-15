from gatekeeper.sources import arbeitnow, hackernews, remoteok
from gatekeeper.sources.base import Anomaly, Posting
from gatekeeper.sources.http import CassetteMiss, Fetcher, Mode, Response

#: The two boards the agent audits. Order is not meaningful.
BOARDS = {
    remoteok.SOURCE_ID: remoteok,
    arbeitnow.SOURCE_ID: arbeitnow,
}

__all__ = [
    "Anomaly",
    "BOARDS",
    "CassetteMiss",
    "Fetcher",
    "Mode",
    "Posting",
    "Response",
    "arbeitnow",
    "hackernews",
    "remoteok",
]
