"""Thread-safe registry for active OpenFlow datapaths."""

from threading import RLock


class DatapathRegistry:
    """Track the latest active datapath object for each DPID."""

    def __init__(self):
        self._datapaths = {}
        self._lock = RLock()

    @staticmethod
    def _get_dpid(datapath):
        dpid = getattr(datapath, "id", None)
        if dpid is None:
            raise ValueError("datapath DPID has not been negotiated")
        return dpid

    def register(self, datapath):
        """Store a datapath and return the previously registered object."""
        dpid = self._get_dpid(datapath)
        with self._lock:
            previous = self._datapaths.get(dpid)
            self._datapaths[dpid] = datapath
            return previous

    def unregister(self, datapath):
        """Remove a datapath only when it is still the active object."""
        dpid = self._get_dpid(datapath)
        with self._lock:
            if self._datapaths.get(dpid) is not datapath:
                return False
            del self._datapaths[dpid]
            return True

    def get(self, dpid):
        with self._lock:
            return self._datapaths.get(dpid)

    def snapshot(self):
        """Return active datapaths ordered deterministically by DPID."""
        with self._lock:
            return tuple(
                self._datapaths[dpid]
                for dpid in sorted(self._datapaths)
            )

    def __len__(self):
        with self._lock:
            return len(self._datapaths)
