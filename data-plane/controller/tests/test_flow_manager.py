import unittest

from os_ken.ofproto import ofproto_v1_3
from os_ken.ofproto import ofproto_v1_3_parser

from app.flow_manager import TABLE_MISS_COOKIE
from app.flow_manager import TABLE_MISS_PRIORITY
from app.flow_manager import TABLE_MISS_TABLE_ID
from app.flow_manager import build_packet_out
from app.flow_manager import install_table_miss_flow
from app.flow_manager import send_packet_out


class FakeDatapath:
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def __init__(self):
        self.sent_messages = []

    def send_msg(self, message):
        self.sent_messages.append(message)


class TableMissFlowTests(unittest.TestCase):
    def test_builds_openflow_13_table_miss_rule(self):
        datapath = FakeDatapath()

        flow_mod = install_table_miss_flow(datapath)

        self.assertEqual([flow_mod], datapath.sent_messages)
        self.assertEqual(TABLE_MISS_COOKIE, flow_mod.cookie)
        self.assertEqual(TABLE_MISS_TABLE_ID, flow_mod.table_id)
        self.assertEqual(TABLE_MISS_PRIORITY, flow_mod.priority)
        self.assertEqual(ofproto_v1_3.OFPFC_ADD, flow_mod.command)
        self.assertEqual(0, flow_mod.idle_timeout)
        self.assertEqual(0, flow_mod.hard_timeout)
        self.assertEqual([], flow_mod.match.to_jsondict()["OFPMatch"]["oxm_fields"])

        instruction = flow_mod.instructions[0]
        self.assertEqual(ofproto_v1_3.OFPIT_APPLY_ACTIONS, instruction.type)
        action = instruction.actions[0]
        self.assertEqual(ofproto_v1_3.OFPP_CONTROLLER, action.port)
        self.assertEqual(ofproto_v1_3.OFPCML_NO_BUFFER, action.max_len)


class PacketOutTests(unittest.TestCase):
    def test_builds_unbuffered_packet_out_with_frame_data(self):
        datapath = FakeDatapath()
        frame = b"ethernet-frame"

        packet_out = build_packet_out(
            datapath=datapath,
            buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
            in_port=1,
            output_ports=(2, 4, 5),
            data=frame,
        )

        self.assertEqual(ofproto_v1_3.OFP_NO_BUFFER, packet_out.buffer_id)
        self.assertEqual(1, packet_out.in_port)
        self.assertEqual([2, 4, 5], [action.port for action in packet_out.actions])
        self.assertEqual(frame, packet_out.data)

    def test_omits_frame_data_when_switch_buffered_packet(self):
        datapath = FakeDatapath()

        packet_out = build_packet_out(
            datapath=datapath,
            buffer_id=7,
            in_port=3,
            output_ports=(1,),
            data=b"unused",
        )

        self.assertEqual(7, packet_out.buffer_id)
        self.assertIsNone(packet_out.data)

    def test_sends_packet_out(self):
        datapath = FakeDatapath()

        packet_out = send_packet_out(
            datapath=datapath,
            buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
            in_port=1,
            output_ports=(2,),
            data=b"frame",
        )

        self.assertEqual([packet_out], datapath.sent_messages)


if __name__ == "__main__":
    unittest.main()
