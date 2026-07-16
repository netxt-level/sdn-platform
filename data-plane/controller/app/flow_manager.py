"""OpenFlow message builders used by the controller application."""

import zlib


TABLE_MISS_COOKIE = 0x53444E0000000001
TABLE_MISS_PRIORITY = 0
TABLE_MISS_TABLE_ID = 0
L2_FORWARDING_COOKIE_PREFIX = 0x53444E1000000000
L2_FORWARDING_COOKIE_MASK = 0xFFFFFFFF00000000
L2_FORWARDING_PRIORITY = 100
L2_FORWARDING_IDLE_TIMEOUT = 60
L2_FORWARDING_HARD_TIMEOUT = 0


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
    destination_mac,
    ethertype,
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
        match=parser.OFPMatch(
            eth_src=source_mac,
            eth_dst=destination_mac,
            eth_type=ethertype,
        ),
        instructions=instructions,
    )


def install_l2_forwarding_flow(
    datapath,
    source_mac,
    destination_mac,
    ethertype,
    output_port,
):
    """Build and send one internal learned-unicast rule."""
    flow_mod = build_l2_forwarding_flow(
        datapath,
        source_mac,
        destination_mac,
        ethertype,
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
