"""OpenFlow message builders used by the controller application."""

TABLE_MISS_COOKIE = 0x53444E0000000001
TABLE_MISS_PRIORITY = 0
TABLE_MISS_TABLE_ID = 0


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
