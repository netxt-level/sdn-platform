import unittest

from os_ken.ofproto import ofproto_v1_3
from os_ken.ofproto import ofproto_v1_3_parser

from app.flow_manager import TABLE_MISS_COOKIE
from app.flow_manager import TABLE_MISS_PRIORITY
from app.flow_manager import TABLE_MISS_TABLE_ID
from app.flow_manager import L2_FORWARDING_COOKIE_MASK
from app.flow_manager import L2_FORWARDING_COOKIE_PREFIX
from app.flow_manager import L2_FORWARDING_HARD_TIMEOUT
from app.flow_manager import L2_FORWARDING_IDLE_TIMEOUT
from app.flow_manager import L2_FORWARDING_PRIORITY
from app.flow_manager import build_l2_forwarding_cookie
from app.flow_manager import build_l2_forwarding_flow
from app.flow_manager import build_packet_out
from app.flow_manager import delete_all_l2_forwarding_flows
from app.flow_manager import delete_l2_forwarding_flows_for_mac
from app.flow_manager import install_table_miss_flow
from app.flow_manager import install_l2_forwarding_flow
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


class L2ForwardingFlowTests(unittest.TestCase):
    SOURCE_MAC = "00:00:00:00:00:01"
    DESTINATION_MAC = "00:00:00:00:01:00"

    def test_cookie_is_stable_and_direction_specific(self):
        cookie = build_l2_forwarding_cookie(
            self.SOURCE_MAC,
            self.DESTINATION_MAC,
            0x0800,
        )

        self.assertEqual(
            cookie,
            build_l2_forwarding_cookie(
                self.SOURCE_MAC,
                self.DESTINATION_MAC,
                0x0800,
            ),
        )
        self.assertEqual(
            L2_FORWARDING_COOKIE_PREFIX,
            cookie & L2_FORWARDING_COOKIE_MASK,
        )
        self.assertNotEqual(
            cookie,
            build_l2_forwarding_cookie(
                self.DESTINATION_MAC,
                self.SOURCE_MAC,
                0x0800,
            ),
        )
        self.assertNotEqual(
            cookie,
            build_l2_forwarding_cookie(
                self.SOURCE_MAC,
                self.DESTINATION_MAC,
                0x0806,
            ),
        )

    def test_builds_l2_forwarding_rule(self):
        datapath = FakeDatapath()

        flow_mod = build_l2_forwarding_flow(
            datapath=datapath,
            source_mac=self.SOURCE_MAC,
            destination_mac=self.DESTINATION_MAC,
            ethertype=0x0800,
            output_port=4,
        )

        self.assertEqual(L2_FORWARDING_PRIORITY, flow_mod.priority)
        self.assertEqual(L2_FORWARDING_IDLE_TIMEOUT, flow_mod.idle_timeout)
        self.assertEqual(L2_FORWARDING_HARD_TIMEOUT, flow_mod.hard_timeout)
        self.assertEqual(self.SOURCE_MAC, flow_mod.match["eth_src"])
        self.assertEqual(self.DESTINATION_MAC, flow_mod.match["eth_dst"])
        self.assertEqual(0x0800, flow_mod.match["eth_type"])
        action = flow_mod.instructions[0].actions[0]
        self.assertEqual(4, action.port)

    def test_installs_l2_forwarding_rule(self):
        datapath = FakeDatapath()

        flow_mod = install_l2_forwarding_flow(
            datapath,
            self.SOURCE_MAC,
            self.DESTINATION_MAC,
            0x0800,
            4,
        )

        self.assertEqual([flow_mod], datapath.sent_messages)

    def test_deletes_source_and_destination_rules_for_moved_mac(self):
        datapath = FakeDatapath()

        flow_mods = delete_l2_forwarding_flows_for_mac(
            datapath,
            self.SOURCE_MAC,
        )

        self.assertEqual(list(flow_mods), datapath.sent_messages)
        self.assertEqual(2, len(flow_mods))
        self.assertEqual(
            [ofproto_v1_3.OFPFC_DELETE, ofproto_v1_3.OFPFC_DELETE],
            [flow_mod.command for flow_mod in flow_mods],
        )
        self.assertEqual(
            [self.SOURCE_MAC, self.SOURCE_MAC],
            [
                flow_mod.match.get("eth_src", flow_mod.match.get("eth_dst"))
                for flow_mod in flow_mods
            ],
        )
        for flow_mod in flow_mods:
            self.assertEqual(L2_FORWARDING_COOKIE_PREFIX, flow_mod.cookie)
            self.assertEqual(L2_FORWARDING_COOKIE_MASK, flow_mod.cookie_mask)
            self.assertEqual(ofproto_v1_3.OFPP_ANY, flow_mod.out_port)
            self.assertEqual(ofproto_v1_3.OFPG_ANY, flow_mod.out_group)

    def test_deletes_all_controller_managed_l2_rules(self):
        datapath = FakeDatapath()

        flow_mod = delete_all_l2_forwarding_flows(datapath)

        self.assertEqual([flow_mod], datapath.sent_messages)
        self.assertEqual(ofproto_v1_3.OFPFC_DELETE, flow_mod.command)
        self.assertEqual(L2_FORWARDING_COOKIE_PREFIX, flow_mod.cookie)
        self.assertEqual(L2_FORWARDING_COOKIE_MASK, flow_mod.cookie_mask)
        self.assertEqual(ofproto_v1_3.OFPP_ANY, flow_mod.out_port)
        self.assertEqual(ofproto_v1_3.OFPG_ANY, flow_mod.out_group)
        self.assertEqual(
            [],
            flow_mod.match.to_jsondict()["OFPMatch"]["oxm_fields"],
        )


if __name__ == "__main__":
    unittest.main()
