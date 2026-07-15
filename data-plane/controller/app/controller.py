"""Minimal OpenFlow 1.3 controller used to verify switch connections."""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER
from os_ken.controller.handler import DEAD_DISPATCHER
from os_ken.controller.handler import MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.lib.packet import ether_types
from os_ken.ofproto import ofproto_v1_3

from app.api import ControllerApiServer
from app.config import load_settings
from app.datapaths import DatapathRegistry
from app.flow_manager import TABLE_MISS_COOKIE
from app.flow_manager import install_table_miss_flow
from app.flow_manager import send_packet_out
from app.hosts import HostRegistry
from app.packet_parser import classify_destination
from app.packet_parser import parse_packet_metadata
from app.topology import get_flood_output_ports
from app.topology import is_host_facing_port


FLOOD_ETHERTYPES = frozenset({
    ether_types.ETH_TYPE_ARP,
    ether_types.ETH_TYPE_IP,
})


class SwitchConnectionController(app_manager.OSKenApp):
    """Log OpenFlow switch connection state transitions."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.settings = load_settings()
        self.datapaths = DatapathRegistry()
        self.hosts = HostRegistry()
        self.api_server = ControllerApiServer(
            self.datapaths,
            self.settings,
        )

    def start(self):
        super().start()
        self.api_server.start()
        self.logger.info(
            "rest_api_started host=%s port=%d",
            self.settings.rest_host,
            self.settings.rest_port,
        )

    def stop(self):
        self.api_server.stop()
        super().stop()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_switch_features(self, event):
        datapath = event.msg.datapath
        install_table_miss_flow(datapath)
        self.logger.info(
            "table_miss_installed dpid=%016x cookie=0x%016x",
            datapath.id,
            TABLE_MISS_COOKIE,
        )

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
            previous = self.datapaths.register(datapath)
            if previous is None:
                event_name = "switch_connected"
            elif previous is datapath:
                event_name = "switch_connection_refreshed"
            else:
                event_name = "switch_reconnected"
            self.logger.info(
                "%s dpid=%s connected_switches=%d",
                event_name,
                dpid,
                len(self.datapaths),
            )
        elif event.state == DEAD_DISPATCHER:
            if self.datapaths.unregister(datapath):
                self.logger.info(
                    "switch_disconnected dpid=%s connected_switches=%d",
                    dpid,
                    len(self.datapaths),
                )
            else:
                self.logger.info(
                    "switch_disconnect_ignored dpid=%s reason=stale_datapath",
                    dpid,
                )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, event):
        msg = event.msg
        datapath = msg.datapath
        in_port = msg.match.get("in_port")

        if (
            datapath.id is None
            or not isinstance(in_port, int)
            or in_port <= 0
            or in_port >= datapath.ofproto.OFPP_MAX
        ):
            self.logger.debug(
                "packet_in_ignored reason=invalid_attachment dpid=%s port=%s",
                datapath.id,
                in_port,
            )
            return

        metadata = parse_packet_metadata(msg.data)
        if metadata is None:
            self.logger.debug(
                "packet_in_ignored reason=packet_not_supported dpid=%016x "
                "port=%d",
                datapath.id,
                in_port,
            )
            return

        if is_host_facing_port(datapath.id, in_port):
            self._learn_source_host(datapath, in_port, metadata)

        self._flood_packet(msg, metadata)

    def _learn_source_host(self, datapath, in_port, metadata):
        try:
            result = self.hosts.learn(
                mac=metadata.source_mac,
                ipv4=metadata.source_ipv4,
                dpid=datapath.id,
                port=in_port,
            )
        except ValueError as error:
            self.logger.warning(
                "host_learning_rejected dpid=%016x port=%d reason=%s",
                datapath.id,
                in_port,
                error,
            )
            return

        log = self.logger.debug
        if result.change != "refreshed":
            log = self.logger.info
        log(
            "host_%s mac=%s ipv4=%s dpid=%016x port=%d",
            result.change,
            result.current.mac,
            result.current.ipv4 or "unknown",
            result.current.dpid,
            result.current.port,
        )

    def _flood_packet(self, msg, metadata):
        datapath = msg.datapath
        in_port = msg.match["in_port"]

        if metadata.ethertype not in FLOOD_ETHERTYPES:
            self.logger.debug(
                "packet_in_ignored reason=ethertype_not_supported "
                "dpid=%016x port=%d ethertype=0x%04x",
                datapath.id,
                in_port,
                metadata.ethertype,
            )
            return

        output_ports = get_flood_output_ports(datapath.id, in_port)
        if not output_ports:
            self.logger.debug(
                "packet_out_skipped reason=no_flood_port dpid=%016x port=%d",
                datapath.id,
                in_port,
            )
            return

        send_packet_out(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            output_ports=output_ports,
            data=msg.data,
        )
        self.logger.debug(
            "packet_out_flooded kind=%s dpid=%016x in_port=%d "
            "out_ports=%s",
            classify_destination(metadata.destination_mac),
            datapath.id,
            in_port,
            ",".join(str(port) for port in output_ports),
        )
