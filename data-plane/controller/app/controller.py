"""Minimal OpenFlow 1.3 controller used to verify switch connections."""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import DEAD_DISPATCHER
from os_ken.controller.handler import MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3


class SwitchConnectionController(app_manager.OSKenApp):
    """Log OpenFlow switch connection state transitions."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER],
    )
    def handle_datapath_state_change(self, event):
        datapath = event.datapath

        if datapath.id is None:
            self.logger.debug(
                "switch_state_ignored reason=dpid_not_negotiated state=%s",
                event.state,
            )
            return

        dpid = f"{datapath.id:016x}"

        if event.state == MAIN_DISPATCHER:
            self.logger.info("switch_connected dpid=%s", dpid)
        elif event.state == DEAD_DISPATCHER:
            self.logger.info("switch_disconnected dpid=%s", dpid)
