"""OpenFlow message builders used by the controller application."""

import hashlib
import zlib


TABLE_MISS_COOKIE = 0x53444E0000000001
TABLE_MISS_PRIORITY = 0
TABLE_MISS_TABLE_ID = 0
L2_FORWARDING_COOKIE_PREFIX = 0x53444E1000000000
L2_FORWARDING_COOKIE_MASK = 0xFFFFFFFF00000000
L2_FORWARDING_PRIORITY = 100
L2_FORWARDING_IDLE_TIMEOUT = 60
L2_FORWARDING_HARD_TIMEOUT = 0
EXTERNAL_FLOW_COOKIE_PREFIX = 0x5344E20000000000
EXTERNAL_FLOW_COOKIE_MASK = 0xFFFFFF0000000000
EXTERNAL_FLOW_TABLE_ID = 0

EXTERNAL_MATCH_FIELDS = frozenset({
    "eth_src",
    "eth_dst",
    "eth_type",
    "ipv4_src",
    "ipv4_dst",
    "ip_proto",
    "tcp_src",
    "tcp_dst",
    "udp_src",
    "udp_dst",
    "icmpv4_type",
    "icmpv4_code",
})
INTEGER_MATCH_FIELDS = frozenset({
    "eth_type",
    "ip_proto",
    "tcp_src",
    "tcp_dst",
    "udp_src",
    "udp_dst",
    "icmpv4_type",
    "icmpv4_code",
})


def build_table_miss_flow(datapath):
    """Build the default rule that sends unmatched packets to the controller."""
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    actions = [
        parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER,
        )
    ]
    instructions = [
        parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS,
            actions,
        )
    ]

    return parser.OFPFlowMod(
        datapath=datapath,
        cookie=TABLE_MISS_COOKIE,
        table_id=TABLE_MISS_TABLE_ID,
        command=ofproto.OFPFC_ADD,
        idle_timeout=0,
        hard_timeout=0,
        priority=TABLE_MISS_PRIORITY,
        match=parser.OFPMatch(),
        instructions=instructions,
    )


def install_table_miss_flow(datapath):
    """Install or replace the table-miss rule on a datapath."""
    flow_mod = build_table_miss_flow(datapath)
    datapath.send_msg(flow_mod)
    return flow_mod


def install_table_miss_with_barrier(datapath):
    """Install Table-Miss and request completion of preceding messages."""
    flow_mod = install_table_miss_flow(datapath)
    barrier_request = datapath.ofproto_parser.OFPBarrierRequest(datapath)
    datapath.send_msg(barrier_request)
    return flow_mod, barrier_request


def build_port_description_request(datapath):
    """Build a request for the switch's current OpenFlow port state."""
    return datapath.ofproto_parser.OFPPortDescStatsRequest(datapath, 0)


def request_port_descriptions(datapath):
    """Request a fresh port-state snapshot after a switch connects."""
    request = build_port_description_request(datapath)
    datapath.send_msg(request)
    return request


def build_packet_out(datapath, buffer_id, in_port, output_ports, data):
    """Build a Packet-Out for the selected physical output ports."""
    parser = datapath.ofproto_parser
    actions = [parser.OFPActionOutput(port) for port in output_ports]
    packet_data = data
    if buffer_id != datapath.ofproto.OFP_NO_BUFFER:
        packet_data = None

    return parser.OFPPacketOut(
        datapath=datapath,
        buffer_id=buffer_id,
        in_port=in_port,
        actions=actions,
        data=packet_data,
    )


def send_packet_out(datapath, buffer_id, in_port, output_ports, data):
    """Build and send a Packet-Out message."""
    packet_out = build_packet_out(
        datapath,
        buffer_id,
        in_port,
        output_ports,
        data,
    )
    datapath.send_msg(packet_out)
    return packet_out


def build_l2_forwarding_cookie(source_mac, destination_mac, ethertype):
    """Build a stable internal cookie for one L2 direction and Ethertype."""
    identity = (
        f"{source_mac.lower()}>{destination_mac.lower()}:"
        f"{ethertype:04x}"
    ).encode("ascii")
    return L2_FORWARDING_COOKIE_PREFIX | zlib.crc32(identity)


def build_l2_forwarding_flow(
    datapath,
    source_mac,
    source_ipv4,
    destination_mac,
    ethertype,
    input_port,
    output_port,
):
    """Build an internal learned-unicast forwarding rule."""
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    actions = [parser.OFPActionOutput(output_port)]
    instructions = [
        parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS,
            actions,
        )
    ]
    match_fields = {
        "in_port": input_port,
        "eth_src": source_mac,
        "eth_dst": destination_mac,
        "eth_type": ethertype,
    }
    if ethertype == 0x0800:
        match_fields["ipv4_src"] = source_ipv4
    elif ethertype == 0x0806:
        match_fields["arp_spa"] = source_ipv4

    return parser.OFPFlowMod(
        datapath=datapath,
        cookie=build_l2_forwarding_cookie(
            source_mac,
            destination_mac,
            ethertype,
        ),
        table_id=TABLE_MISS_TABLE_ID,
        command=ofproto.OFPFC_ADD,
        idle_timeout=L2_FORWARDING_IDLE_TIMEOUT,
        hard_timeout=L2_FORWARDING_HARD_TIMEOUT,
        priority=L2_FORWARDING_PRIORITY,
        match=parser.OFPMatch(**match_fields),
        instructions=instructions,
    )


def install_l2_forwarding_flow(
    datapath,
    source_mac,
    source_ipv4,
    destination_mac,
    ethertype,
    input_port,
    output_port,
):
    """Build and send one internal learned-unicast rule."""
    flow_mod = build_l2_forwarding_flow(
        datapath,
        source_mac,
        source_ipv4,
        destination_mac,
        ethertype,
        input_port,
        output_port,
    )
    datapath.send_msg(flow_mod)
    return flow_mod


def delete_l2_forwarding_flows_for_mac(datapath, mac):
    """Delete internal L2 rules where the MAC is source or destination."""
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    flow_mods = []

    for match_field in ("eth_src", "eth_dst"):
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=L2_FORWARDING_COOKIE_PREFIX,
            cookie_mask=L2_FORWARDING_COOKIE_MASK,
            table_id=TABLE_MISS_TABLE_ID,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(**{match_field: mac}),
        )
        datapath.send_msg(flow_mod)
        flow_mods.append(flow_mod)

    return tuple(flow_mods)


def delete_all_l2_forwarding_flows(datapath):
    """Delete all Controller-managed learned-unicast rules on a datapath."""
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    flow_mod = parser.OFPFlowMod(
        datapath=datapath,
        cookie=L2_FORWARDING_COOKIE_PREFIX,
        cookie_mask=L2_FORWARDING_COOKIE_MASK,
        table_id=TABLE_MISS_TABLE_ID,
        command=ofproto.OFPFC_DELETE,
        out_port=ofproto.OFPP_ANY,
        out_group=ofproto.OFPG_ANY,
        match=parser.OFPMatch(),
    )
    datapath.send_msg(flow_mod)
    return flow_mod


def build_external_flow_cookie(rule_id):
    """Build a stable cookie in the external/backend-managed cookie range."""
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError("rule_id must be a non-empty string")
    digest = hashlib.blake2b(
        rule_id.strip().encode("utf-8"),
        digest_size=5,
    ).digest()
    return EXTERNAL_FLOW_COOKIE_PREFIX | int.from_bytes(digest, "big")


def normalize_external_match(match):
    """Validate backend match fields and add required protocol prerequisites."""
    if not isinstance(match, dict) or not match:
        raise ValueError("match must contain at least one field")

    unsupported = sorted(set(match) - EXTERNAL_MATCH_FIELDS)
    if unsupported:
        raise ValueError(
            "unsupported match fields: " + ", ".join(unsupported)
        )

    normalized = dict(match)
    for field in INTEGER_MATCH_FIELDS:
        if field not in normalized:
            continue
        value = normalized[field]
        if isinstance(value, bool):
            raise ValueError(f"{field} must be an integer")
        try:
            normalized[field] = int(value)
        except (TypeError, ValueError) as error:
            raise ValueError(f"{field} must be an integer") from error

    ip_fields = {
        "ipv4_src",
        "ipv4_dst",
        "ip_proto",
        "tcp_src",
        "tcp_dst",
        "udp_src",
        "udp_dst",
        "icmpv4_type",
        "icmpv4_code",
    }
    if set(normalized) & ip_fields:
        eth_type = normalized.setdefault("eth_type", 0x0800)
        if eth_type != 0x0800:
            raise ValueError("IPv4 match fields require eth_type=2048")

    protocol_requirements = (
        ({"tcp_src", "tcp_dst"}, 6, "TCP"),
        ({"udp_src", "udp_dst"}, 17, "UDP"),
        ({"icmpv4_type", "icmpv4_code"}, 1, "ICMP"),
    )
    for fields, protocol, name in protocol_requirements:
        if not set(normalized) & fields:
            continue
        configured = normalized.setdefault("ip_proto", protocol)
        if configured != protocol:
            raise ValueError(
                f"{name} match fields require ip_proto={protocol}"
            )

    return normalized


def resolve_external_output_port(datapath, action, switch_link_ports):
    """Resolve OUTPUT:<port|switch> to a physical port on the target switch."""
    if not isinstance(action, str):
        raise ValueError("action must be a string")
    prefix, separator, raw_target = action.strip().partition(":")
    if prefix.upper() != "OUTPUT" or not separator or not raw_target.strip():
        raise ValueError("OUTPUT action must use OUTPUT:<port|switch>")

    target = raw_target.strip().lower()
    if target.startswith("s") and target[1:].isdigit():
        neighbor = int(target[1:])
        try:
            return switch_link_ports[datapath.id][neighbor]
        except KeyError as error:
            raise ValueError(
                f"switch s{neighbor} is not adjacent to s{datapath.id}"
            ) from error

    try:
        port = int(target)
    except ValueError as error:
        raise ValueError(
            "OUTPUT target must be a port number or adjacent switch"
        ) from error
    if port <= 0 or port >= datapath.ofproto.OFPP_MAX:
        raise ValueError(f"invalid OUTPUT port: {port}")
    return port


def build_external_flow(
    datapath,
    *,
    rule_id,
    match,
    action,
    priority,
    idle_timeout=0,
    hard_timeout=0,
    switch_link_ports=None,
):
    """Build a backend-managed DROP or OUTPUT OpenFlow 1.3 rule."""
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    normalized_match = normalize_external_match(match)
    normalized_action = str(action).strip()

    if normalized_action.upper() == "DROP":
        instructions = []
    elif normalized_action.upper() == "RATE_LIMIT":
        raise ValueError(
            "RATE_LIMIT requires the OVS Meter pipeline and is not supported yet"
        )
    elif normalized_action.upper().startswith("OUTPUT"):
        output_port = resolve_external_output_port(
            datapath,
            normalized_action,
            switch_link_ports or {},
        )
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(output_port)],
            )
        ]
    else:
        raise ValueError(f"unsupported action: {action}")

    return parser.OFPFlowMod(
        datapath=datapath,
        cookie=build_external_flow_cookie(rule_id),
        table_id=EXTERNAL_FLOW_TABLE_ID,
        command=ofproto.OFPFC_ADD,
        idle_timeout=0 if idle_timeout is None else int(idle_timeout),
        hard_timeout=0 if hard_timeout is None else int(hard_timeout),
        priority=int(priority),
        flags=ofproto.OFPFF_SEND_FLOW_REM,
        match=parser.OFPMatch(**normalized_match),
        instructions=instructions,
    )


def install_external_flow_with_barrier(datapath, **flow):
    """Send one external Flow-Mod followed by a confirmation barrier."""
    flow_mod = build_external_flow(datapath, **flow)
    datapath.send_msg(flow_mod)
    barrier_request = datapath.ofproto_parser.OFPBarrierRequest(datapath)
    datapath.send_msg(barrier_request)
    return flow_mod, barrier_request
