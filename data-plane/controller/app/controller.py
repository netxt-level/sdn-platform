"""Minimal OpenFlow 1.3 controller used to verify switch connections."""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER
from os_ken.controller.handler import DEAD_DISPATCHER
from os_ken.controller.handler import MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.lib.packet import ether_types
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3

from app.api import ControllerApiServer
from app.config import load_settings
from app.datapaths import DatapathRegistry
from app.flow_manager import TABLE_MISS_COOKIE
from app.flow_manager import delete_all_l2_forwarding_flows
from app.flow_manager import delete_l2_forwarding_flows_for_mac
from app.flow_manager import delete_rate_limit_meter
from app.flow_manager import install_table_miss_with_barrier
from app.flow_manager import install_l2_forwarding_flow
from app.flow_manager import request_port_descriptions
from app.flow_manager import request_port_stats
from app.flow_manager import request_flow_stats
from app.flow_manager import send_packet_out
from app.flow_operations import FlowOperationRegistry
from app.hosts import HostRegistry
from app.meters import MeterRegistry
from app.packet_parser import classify_destination
from app.packet_parser import parse_packet_metadata
from app.path_distribution import BALANCED_MODE
from app.path_distribution import PRIMARY_PATH_COSTS
from app.path_distribution import PathDistributionPolicy
from app.path_distribution import prefer_path
from app.routing import RoutingError
from app.routing import calculate_input_ports
from app.routing import calculate_weighted_bidirectional_routes
from app.table_miss import TableMissRegistry
from app.stats import StatsRegistry
from app.topology import ActiveTopology
from app.topology import get_host_binding
from app.topology import get_neighbor_switch
from app.topology import is_host_facing_port
from app.topology import SWITCH_LINK_PORTS
from app.topology import validate_host_source
from app.topology import WEIGHTED_SWITCH_GRAPH


FLOOD_ETHERTYPES = frozenset({
    ether_types.ETH_TYPE_ARP,
    ether_types.ETH_TYPE_IP,
})
L2_FORWARDING_ETHERTYPES = (
    ether_types.ETH_TYPE_ARP,
    ether_types.ETH_TYPE_IP,
)


class SwitchConnectionController(app_manager.OSKenApp):
    """Log OpenFlow switch connection state transitions."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.settings = load_settings()
        self.datapaths = DatapathRegistry()
        self.table_miss_statuses = TableMissRegistry()
        self.flow_operations = FlowOperationRegistry()
        self.meters = MeterRegistry()
        self.hosts = HostRegistry()
        self.topology = ActiveTopology(WEIGHTED_SWITCH_GRAPH)
        self.stats = StatsRegistry()
        self.path_distribution = PathDistributionPolicy(
            threshold_pps=self.settings.path_distribution_threshold_pps,
            recovery_pps=self.settings.path_distribution_recovery_pps,
        )
        self.stats.update_path_distribution(self.path_distribution.snapshot())
        self._stats_thread = None
        self.api_server = ControllerApiServer(
            self.datapaths,
            self.table_miss_statuses,
            self.flow_operations,
            self.meters,
            self.hosts,
            self.topology,
            self._invalidate_all_l2_flows,
            self.stats,
            self.settings,
        )

    def start(self):
        super().start()
        self.api_server.start()
        self._stats_thread = hub.spawn(self._monitor_stats)
        self.logger.info(
            "rest_api_started host=%s port=%d",
            self.settings.rest_host,
            self.settings.rest_port,
        )

    def stop(self):
        if self._stats_thread is not None:
            hub.kill(self._stats_thread)
            self._stats_thread = None
        self.api_server.stop()
        super().stop()

    def _monitor_stats(self):
        while True:
            for datapath in self.datapaths.snapshot():
                request_port_stats(datapath)
                request_flow_stats(datapath)
            hub.sleep(self.settings.stats_interval_seconds)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def handle_port_stats_reply(self, event):
        datapath = event.msg.datapath
        entries = tuple(event.msg.body)
        self.stats.update_ports(datapath.id, entries)
        if datapath.id != 1:
            return

        update = self.path_distribution.update_s1_port_stats(entries)
        self.stats.update_path_distribution(self.path_distribution.snapshot())
        if not update.changed:
            return

        if update.mode != BALANCED_MODE:
            self.topology.set_link_costs(PRIMARY_PATH_COSTS)
        invalidated = self._invalidate_all_l2_flows(
            f"path_distribution:{update.mode}",
        )
        self.logger.info(
            "path_distribution_changed mode=%s pps=%.2f threshold_pps=%.2f "
            "recovery_pps=%.2f invalidated_switches=%d",
            update.mode,
            update.pps,
            self.path_distribution.threshold_pps,
            self.path_distribution.recovery_pps,
            invalidated,
        )

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def handle_flow_stats_reply(self, event):
        self.stats.update_flows(event.msg.datapath.id, event.msg.body)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_switch_features(self, event):
        datapath = event.msg.datapath
        flow_mods, barrier_request = install_table_miss_with_barrier(datapath)
        self.table_miss_statuses.begin(
            datapath,
            flow_xids=tuple(flow_mod.xid for flow_mod in flow_mods),
            barrier_xid=barrier_request.xid,
        )
        self.logger.info(
            "table_miss_pending dpid=%016x cookie=0x%016x "
            "flow_xids=%s barrier_xid=%d",
            datapath.id,
            TABLE_MISS_COOKIE,
            ",".join(str(flow_mod.xid) for flow_mod in flow_mods),
            barrier_request.xid,
        )

    @set_ev_cls(
        ofp_event.EventOFPBarrierReply,
        [CONFIG_DISPATCHER, MAIN_DISPATCHER],
    )
    def handle_barrier_reply(self, event):
        msg = event.msg
        if self.table_miss_statuses.mark_installed(
            msg.datapath,
            msg.xid,
        ):
            self.logger.info(
                "table_miss_installed dpid=%016x barrier_xid=%d",
                msg.datapath.id,
                msg.xid,
            )
        elif status := self.flow_operations.mark_confirmed(
            msg.datapath,
            msg.xid,
        ):
            if status.state == "installed":
                self.logger.info(
                    "external_flow_installed dpid=%016x rule_id=%s "
                    "barrier_xid=%d",
                    msg.datapath.id,
                    status.rule_id,
                    msg.xid,
                )
            else:
                self.logger.info(
                    "external_flow_removed dpid=%016x rule_id=%s "
                    "barrier_xid=%d",
                    msg.datapath.id,
                    status.rule_id,
                    msg.xid,
                )
        else:
            self.logger.debug(
                "barrier_reply_untracked dpid=%016x xid=%d",
                msg.datapath.id,
                msg.xid,
            )

    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [CONFIG_DISPATCHER, MAIN_DISPATCHER],
    )
    def handle_openflow_error(self, event):
        msg = event.msg
        reason = f"OpenFlow error type={msg.type} code={msg.code}"
        if self.table_miss_statuses.mark_failed(
            msg.datapath,
            msg.xid,
            reason,
        ):
            self.logger.error(
                "table_miss_failed dpid=%016x xid=%d type=%d code=%d",
                msg.datapath.id,
                msg.xid,
                msg.type,
                msg.code,
            )
        elif rule_id := self.flow_operations.mark_failed(
            msg.datapath,
            msg.xid,
            reason,
        ):
            self.logger.error(
                "external_flow_failed dpid=%016x rule_id=%s xid=%d "
                "type=%d code=%d",
                msg.datapath.id,
                rule_id,
                msg.xid,
                msg.type,
                msg.code,
            )
        else:
            self.logger.warning(
                "openflow_error_untracked dpid=%016x xid=%d "
                "type=%d code=%d",
                msg.datapath.id,
                msg.xid,
                msg.type,
                msg.code,
            )

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def handle_flow_removed(self, event):
        msg = event.msg
        reasons = {
            msg.datapath.ofproto.OFPRR_IDLE_TIMEOUT: "expired",
            msg.datapath.ofproto.OFPRR_HARD_TIMEOUT: "expired",
            msg.datapath.ofproto.OFPRR_DELETE: "removed",
            msg.datapath.ofproto.OFPRR_GROUP_DELETE: "removed",
        }
        state = reasons.get(msg.reason, "removed")
        status = self.flow_operations.mark_removed(
            msg.datapath,
            msg.cookie,
            state,
        )
        if status is None:
            return

        if status.meter_id is not None:
            unused_meter_id = self.meters.release(
                status.dpid,
                status.rule_id,
            )
            if unused_meter_id is not None:
                delete_rate_limit_meter(msg.datapath, unused_meter_id)
                self.logger.info(
                    "meter_removed dpid=%016x meter_id=%d rule_id=%s",
                    status.dpid,
                    unused_meter_id,
                    status.rule_id,
                )
        self.logger.info(
            "external_flow_%s dpid=%016x rule_id=%s cookie=0x%016x",
            state,
            status.dpid,
            status.rule_id,
            status.cookie,
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
            try:
                topology_changed = self.topology.connect_switch(datapath.id)
                if topology_changed:
                    request_port_descriptions(datapath)
                    self.logger.info(
                        "port_description_requested dpid=%s",
                        dpid,
                    )
            except ValueError as error:
                topology_changed = False
                self.logger.warning(
                    "topology_switch_ignored dpid=%s reason=%s",
                    dpid,
                    error,
                )
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
            if topology_changed:
                self.logger.info(
                    "topology_switch_activated dpid=%s active_switches=%d",
                    dpid,
                    len(self.topology.snapshot()),
                )
                self._invalidate_all_l2_flows(
                    reason=f"switch_connected:{dpid}",
                )
        elif event.state == DEAD_DISPATCHER:
            if self.datapaths.unregister(datapath):
                self.table_miss_statuses.remove(datapath)
                failed_rule_ids = self.flow_operations.fail_pending_for_datapath(
                    datapath,
                    "switch disconnected before Barrier Reply",
                )
                for rule_id in failed_rule_ids:
                    self.logger.error(
                        "external_flow_failed dpid=%s rule_id=%s "
                        "reason=switch_disconnected",
                        dpid,
                        rule_id,
                    )
                released_meter_ids = self.meters.release_datapath(datapath.id)
                if released_meter_ids:
                    self.logger.info(
                        "meters_released dpid=%s meter_ids=%s",
                        dpid,
                        ",".join(str(item) for item in released_meter_ids),
                    )
                topology_changed = False
                try:
                    topology_changed = self.topology.disconnect_switch(
                        datapath.id,
                    )
                except ValueError as error:
                    self.logger.warning(
                        "topology_switch_disconnect_ignored dpid=%s "
                        "reason=%s",
                        dpid,
                        error,
                    )
                if topology_changed:
                    self._invalidate_all_l2_flows(
                        reason=f"switch_disconnected:{dpid}",
                    )
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

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def handle_port_status(self, event):
        msg = event.msg
        datapath = msg.datapath
        port = msg.desc.port_no
        neighbor = get_neighbor_switch(datapath.id, port)
        if neighbor is None:
            self.logger.debug(
                "topology_port_ignored dpid=%016x port=%d "
                "reason=not_switch_link",
                datapath.id,
                port,
            )
            return

        try:
            active = self._port_is_active(msg)
        except ValueError as error:
            self.logger.warning(
                "topology_port_rejected dpid=%016x port=%d "
                "source=port_status reason=%s",
                datapath.id,
                port,
                error,
            )
            return

        self._update_link_port_state(
            datapath=datapath,
            port=port,
            neighbor=neighbor,
            active=active,
            source="port_status",
        )

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def handle_port_description_reply(self, event):
        msg = event.msg
        datapath = msg.datapath
        synchronized_ports = 0

        for description in msg.body:
            port = description.port_no
            neighbor = get_neighbor_switch(datapath.id, port)
            if neighbor is None:
                continue
            self._update_link_port_state(
                datapath=datapath,
                port=port,
                neighbor=neighbor,
                active=self._port_description_is_active(
                    datapath,
                    description,
                ),
                source="port_description",
            )
            synchronized_ports += 1

        self.logger.info(
            "port_description_synchronized dpid=%016x transit_ports=%d",
            datapath.id,
            synchronized_ports,
        )

    def _update_link_port_state(
        self,
        datapath,
        port,
        neighbor,
        active,
        source,
    ):
        try:
            topology_changed = self.topology.set_link_port_state(
                datapath.id,
                neighbor,
                active,
            )
        except ValueError as error:
            self.logger.warning(
                "topology_port_rejected dpid=%016x port=%d source=%s "
                "reason=%s",
                datapath.id,
                port,
                source,
                error,
            )
            return

        if not topology_changed:
            self.logger.debug(
                "topology_link_unchanged source=%016x destination=%016x "
                "port=%d active=%s event_source=%s",
                datapath.id,
                neighbor,
                port,
                active,
                source,
            )
            return

        state = "up" if active else "down"
        self.logger.info(
            "topology_link_%s source=%016x destination=%016x port=%d "
            "event_source=%s",
            state,
            datapath.id,
            neighbor,
            port,
            source,
        )
        self._invalidate_all_l2_flows(
            reason=f"link_{state}:{datapath.id}-{neighbor}",
        )

    @staticmethod
    def _port_is_active(msg):
        ofproto = msg.datapath.ofproto
        if msg.reason == ofproto.OFPPR_DELETE:
            return False
        if msg.reason not in (ofproto.OFPPR_ADD, ofproto.OFPPR_MODIFY):
            raise ValueError(f"unknown port status reason: {msg.reason}")

        return SwitchConnectionController._port_description_is_active(
            msg.datapath,
            msg.desc,
        )

    @staticmethod
    def _port_description_is_active(datapath, description):
        ofproto = datapath.ofproto
        inactive_state = ofproto.OFPPS_LINK_DOWN | ofproto.OFPPS_BLOCKED
        return not (
            description.config & ofproto.OFPPC_PORT_DOWN
            or description.state & inactive_state
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

        if metadata.ethertype not in FLOOD_ETHERTYPES:
            self.logger.debug(
                "packet_in_ignored reason=ethertype_not_supported "
                "dpid=%016x port=%d ethertype=0x%04x",
                datapath.id,
                in_port,
                metadata.ethertype,
            )
            return

        if is_host_facing_port(datapath.id, in_port):
            rejection_reason = validate_host_source(
                datapath.id,
                in_port,
                metadata.source_mac,
                metadata.source_ipv4,
            )
            if rejection_reason is not None:
                binding = get_host_binding(datapath.id, in_port)
                self.logger.warning(
                    "host_spoof_rejected dpid=%016x port=%d reason=%s "
                    "expected_mac=%s expected_ipv4=%s observed_mac=%s "
                    "observed_ipv4=%s",
                    datapath.id,
                    in_port,
                    rejection_reason,
                    binding.mac,
                    binding.ipv4,
                    metadata.source_mac,
                    metadata.source_ipv4 or "unknown",
                )
                return
            self._learn_source_host(datapath, in_port, metadata)

        if (
            metadata.ethertype in FLOOD_ETHERTYPES
            and classify_destination(metadata.destination_mac)
            == "unknown_unicast"
            and self._forward_known_unicast(msg, metadata)
        ):
            return

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

        if result.change == "moved":
            self._invalidate_host_flows(result.current.mac)

    def _invalidate_host_flows(self, mac):
        datapaths = self.datapaths.snapshot()
        for datapath in datapaths:
            delete_l2_forwarding_flows_for_mac(datapath, mac)
        self.logger.info(
            "l2_flows_invalidated mac=%s switches=%d",
            mac,
            len(datapaths),
        )

    def _invalidate_all_l2_flows(self, reason):
        datapaths = self.datapaths.snapshot()
        for datapath in datapaths:
            delete_all_l2_forwarding_flows(datapath)
        self.logger.info(
            "l2_flows_invalidated reason=%s switches=%d",
            reason,
            len(datapaths),
        )
        return len(datapaths)

    def _forward_known_unicast(self, msg, metadata):
        source = self.hosts.get(metadata.source_mac)
        destination = self.hosts.get(metadata.destination_mac)
        if source is None or destination is None:
            return False

        graph = self.topology.snapshot()
        distribution_mode = self.path_distribution.mode
        preferred_path = None
        if distribution_mode == BALANCED_MODE:
            preferred_path = self.path_distribution.select_path(metadata)
            graph = prefer_path(graph, preferred_path)

        try:
            routes = calculate_weighted_bidirectional_routes(
                graph=graph,
                link_ports=SWITCH_LINK_PORTS,
                source_dpid=source.dpid,
                source_port=source.port,
                destination_dpid=destination.dpid,
                destination_port=destination.port,
            )
        except RoutingError as error:
            self.logger.warning(
                "l2_route_failed src=%s dst=%s reason=%s",
                source.mac,
                destination.mac,
                error,
            )
            return False

        route_dpids = {
            hop.dpid
            for route in (routes.forward, routes.reverse)
            for hop in route.hops
        }
        route_datapaths = {
            dpid: self.datapaths.get(dpid)
            for dpid in route_dpids
        }
        missing_dpids = sorted(
            dpid
            for dpid, datapath in route_datapaths.items()
            if datapath is None
        )
        if missing_dpids:
            self.logger.warning(
                "l2_route_failed src=%s dst=%s missing_switches=%s",
                source.mac,
                destination.mac,
                ",".join(f"{dpid:016x}" for dpid in missing_dpids),
            )
            return False

        current_hop = next(
            (
                hop
                for hop in routes.forward.hops
                if hop.dpid == msg.datapath.id
            ),
            None,
        )
        if current_hop is None:
            self.logger.warning(
                "l2_route_failed src=%s dst=%s packet_switch=%016x "
                "reason=switch_not_on_path",
                source.mac,
                destination.mac,
                msg.datapath.id,
            )
            return False

        ethertypes = L2_FORWARDING_ETHERTYPES
        forward_match = None
        reverse_match = None
        if distribution_mode == BALANCED_MODE:
            ethertypes = (metadata.ethertype,)
            if metadata.ethertype == ether_types.ETH_TYPE_IP:
                forward_match, reverse_match = self._ipv4_flow_matches(metadata)

        self._install_route_flows(
            routes.forward,
            route_datapaths,
            source.mac,
            source.ipv4,
            destination.mac,
            source.port,
            ethertypes=ethertypes,
            flow_match=forward_match,
        )
        self._install_route_flows(
            routes.reverse,
            route_datapaths,
            destination.mac,
            destination.ipv4,
            source.mac,
            destination.port,
            ethertypes=ethertypes,
            flow_match=reverse_match,
        )
        send_packet_out(
            datapath=msg.datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match["in_port"],
            output_ports=(current_hop.output_port,),
            data=msg.data,
        )
        path_log = (
            self.logger.debug
            if distribution_mode == BALANCED_MODE
            else self.logger.info
        )
        path_log(
            "l2_path_installed src=%s dst=%s forward=%s reverse=%s "
            "distribution_mode=%s preferred_path=%s",
            source.mac,
            destination.mac,
            "-".join(str(dpid) for dpid in routes.forward.switches),
            "-".join(str(dpid) for dpid in routes.reverse.switches),
            distribution_mode,
            preferred_path or "configured",
        )
        return True

    @staticmethod
    def _ipv4_flow_matches(metadata):
        if (
            metadata.source_ipv4 is None
            or metadata.destination_ipv4 is None
            or metadata.ip_proto is None
        ):
            return None, None

        forward = {
            "ipv4_src": metadata.source_ipv4,
            "ipv4_dst": metadata.destination_ipv4,
            "ip_proto": metadata.ip_proto,
        }
        reverse = {
            "ipv4_src": metadata.destination_ipv4,
            "ipv4_dst": metadata.source_ipv4,
            "ip_proto": metadata.ip_proto,
        }
        if (
            metadata.source_port is not None
            and metadata.destination_port is not None
        ):
            if metadata.ip_proto == 6:
                source_field = "tcp_src"
                destination_field = "tcp_dst"
            elif metadata.ip_proto == 17:
                source_field = "udp_src"
                destination_field = "udp_dst"
            else:
                return forward, reverse
            forward[source_field] = metadata.source_port
            forward[destination_field] = metadata.destination_port
            reverse[source_field] = metadata.destination_port
            reverse[destination_field] = metadata.source_port
        return forward, reverse

    @staticmethod
    def _install_route_flows(
        route,
        datapaths,
        source_mac,
        source_ipv4,
        destination_mac,
        source_port,
        *,
        ethertypes=L2_FORWARDING_ETHERTYPES,
        flow_match=None,
    ):
        input_ports = calculate_input_ports(
            route.switches,
            SWITCH_LINK_PORTS,
            source_port,
        )
        for hop, input_port in zip(route.hops, input_ports):
            for ethertype in ethertypes:
                install_l2_forwarding_flow(
                    datapath=datapaths[hop.dpid],
                    source_mac=source_mac,
                    source_ipv4=source_ipv4,
                    destination_mac=destination_mac,
                    ethertype=ethertype,
                    input_port=input_port,
                    output_port=hop.output_port,
                    flow_match=flow_match,
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

        output_ports = self.topology.get_flood_output_ports(
            datapath.id,
            in_port,
        )
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
