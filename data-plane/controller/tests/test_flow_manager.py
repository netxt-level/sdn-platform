import unittest

from os_ken.ofproto import ofproto_v1_3
from os_ken.ofproto import ofproto_v1_3_parser

from app.flow_manager import TABLE_MISS_COOKIE
from app.flow_manager import POLICY_TABLE_ID
from app.flow_manager import FORWARDING_TABLE_ID
from app.flow_manager import TABLE_MISS_PRIORITY
from app.flow_manager import TABLE_MISS_TABLE_ID
from app.flow_manager import L2_FORWARDING_COOKIE_MASK
from app.flow_manager import L2_FORWARDING_COOKIE_PREFIX
from app.flow_manager import L2_FORWARDING_HARD_TIMEOUT
from app.flow_manager import L2_FORWARDING_IDLE_TIMEOUT
from app.flow_manager import L2_FORWARDING_PRIORITY
from app.flow_manager import L2_FLOW_FORWARDING_PRIORITY
from app.flow_manager import EXTERNAL_FLOW_COOKIE_PREFIX
from app.flow_manager import build_external_flow
from app.flow_manager import build_external_flow_delete
from app.flow_manager import build_external_flow_cookie
from app.flow_manager import build_policy_table_miss_flow
from app.flow_manager import build_rate_limit_meter
from app.flow_manager import build_l2_forwarding_cookie
from app.flow_manager import build_l2_forwarding_flow
from app.flow_manager import build_packet_out
from app.flow_manager import build_port_description_request
from app.flow_manager import delete_all_l2_forwarding_flows
from app.flow_manager import delete_external_flow_with_barrier
from app.flow_manager import delete_l2_forwarding_flows_for_mac
from app.flow_manager import install_table_miss_flow
from app.flow_manager import install_table_miss_with_barrier
from app.flow_manager import install_l2_forwarding_flow
from app.flow_manager import request_port_descriptions
from app.flow_manager import send_packet_out


class FakeDatapath:
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def __init__(self):
        self.sent_messages = []
        self.next_xid = 0

    def send_msg(self, message):
        if message.xid is None:
            self.next_xid += 1
            message.set_xid(self.next_xid)
        self.sent_messages.append(message)


class TableMissFlowTests(unittest.TestCase):
    def test_builds_openflow_13_table_miss_rule(self):
        datapath = FakeDatapath()

        flow_mod = install_table_miss_flow(datapath)

        self.assertEqual([flow_mod], datapath.sent_messages)
        self.assertEqual(TABLE_MISS_COOKIE, flow_mod.cookie)
        self.assertEqual(TABLE_MISS_TABLE_ID, flow_mod.table_id)
        self.assertEqual(FORWARDING_TABLE_ID, flow_mod.table_id)
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

    def test_sends_table_miss_before_barrier_request(self):
        datapath = FakeDatapath()

        flow_mods, barrier_request = install_table_miss_with_barrier(datapath)

        self.assertEqual(
            [*flow_mods, barrier_request],
            datapath.sent_messages,
        )
        self.assertEqual([1, 2], [flow_mod.xid for flow_mod in flow_mods])
        self.assertEqual(3, barrier_request.xid)

    def test_policy_table_miss_continues_to_forwarding_table(self):
        flow_mod = build_policy_table_miss_flow(FakeDatapath())

        self.assertEqual(POLICY_TABLE_ID, flow_mod.table_id)
        self.assertEqual(
            FORWARDING_TABLE_ID,
            flow_mod.instructions[0].table_id,
        )


class PortDescriptionRequestTests(unittest.TestCase):
    def test_builds_openflow_port_description_request(self):
        datapath = FakeDatapath()

        request = build_port_description_request(datapath)

        self.assertIs(datapath, request.datapath)
        self.assertEqual(0, request.flags)

    def test_sends_openflow_port_description_request(self):
        datapath = FakeDatapath()

        request = request_port_descriptions(datapath)

        self.assertEqual([request], datapath.sent_messages)


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
            source_ipv4="10.0.0.1",
            destination_mac=self.DESTINATION_MAC,
            ethertype=0x0800,
            input_port=1,
            output_port=4,
        )

        self.assertEqual(L2_FORWARDING_PRIORITY, flow_mod.priority)
        self.assertEqual(L2_FORWARDING_IDLE_TIMEOUT, flow_mod.idle_timeout)
        self.assertEqual(L2_FORWARDING_HARD_TIMEOUT, flow_mod.hard_timeout)
        self.assertEqual(1, flow_mod.match["in_port"])
        self.assertEqual(self.SOURCE_MAC, flow_mod.match["eth_src"])
        self.assertEqual(self.DESTINATION_MAC, flow_mod.match["eth_dst"])
        self.assertEqual(0x0800, flow_mod.match["eth_type"])
        self.assertEqual("10.0.0.1", flow_mod.match["ipv4_src"])
        action = flow_mod.instructions[0].actions[0]
        self.assertEqual(4, action.port)

    def test_binds_arp_rule_to_source_protocol_address(self):
        datapath = FakeDatapath()

        flow_mod = build_l2_forwarding_flow(
            datapath=datapath,
            source_mac=self.SOURCE_MAC,
            source_ipv4="10.0.0.1",
            destination_mac=self.DESTINATION_MAC,
            ethertype=0x0806,
            input_port=1,
            output_port=4,
        )

        self.assertEqual("10.0.0.1", flow_mod.match["arp_spa"])
        self.assertNotIn("ipv4_src", flow_mod.match)

    def test_builds_higher_priority_tcp_five_tuple_rule(self):
        datapath = FakeDatapath()
        flow_match = {
            "ipv4_src": "10.0.0.1",
            "ipv4_dst": "10.0.0.100",
            "ip_proto": 6,
            "tcp_src": 40123,
            "tcp_dst": 80,
        }

        flow_mod = build_l2_forwarding_flow(
            datapath=datapath,
            source_mac=self.SOURCE_MAC,
            source_ipv4="10.0.0.1",
            destination_mac=self.DESTINATION_MAC,
            ethertype=0x0800,
            input_port=1,
            output_port=5,
            flow_match=flow_match,
        )

        self.assertEqual(L2_FLOW_FORWARDING_PRIORITY, flow_mod.priority)
        for key, value in flow_match.items():
            self.assertEqual(value, flow_mod.match[key])
        self.assertEqual(5, flow_mod.instructions[0].actions[0].port)
        self.assertNotEqual(
            build_l2_forwarding_cookie(
                self.SOURCE_MAC,
                self.DESTINATION_MAC,
                0x0800,
            ),
            flow_mod.cookie,
        )

    def test_installs_l2_forwarding_rule(self):
        datapath = FakeDatapath()

        flow_mod = install_l2_forwarding_flow(
            datapath,
            self.SOURCE_MAC,
            "10.0.0.1",
            self.DESTINATION_MAC,
            0x0800,
            1,
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


class ExternalFlowRuleTests(unittest.TestCase):
    def test_cookie_is_stable_and_in_external_range(self):
        cookie = build_external_flow_cookie("rule-uuid-1")

        self.assertEqual(
            cookie,
            build_external_flow_cookie("rule-uuid-1"),
        )
        self.assertEqual(
            EXTERNAL_FLOW_COOKIE_PREFIX,
            cookie & 0xFFFFFF0000000000,
        )

    def test_builds_drop_rule_with_ipv4_prerequisite(self):
        datapath = FakeDatapath()

        flow_mod = build_external_flow(
            datapath,
            rule_id="rule-1",
            match={"ipv4_src": "10.0.0.2", "ip_proto": 1},
            action="DROP",
            priority=500,
            idle_timeout=60,
            hard_timeout=300,
        )

        self.assertEqual(0x0800, flow_mod.match["eth_type"])
        self.assertEqual("10.0.0.2", flow_mod.match["ipv4_src"])
        self.assertEqual(1, flow_mod.match["ip_proto"])
        self.assertEqual([], flow_mod.instructions)
        self.assertEqual(500, flow_mod.priority)
        self.assertEqual(60, flow_mod.idle_timeout)
        self.assertEqual(300, flow_mod.hard_timeout)

    def test_resolves_adjacent_switch_output_action(self):
        datapath = FakeDatapath()
        datapath.id = 1

        flow_mod = build_external_flow(
            datapath,
            rule_id="rule-2",
            match={"ipv4_dst": "10.0.0.100"},
            action="output:s2",
            priority=500,
            switch_link_ports={1: {2: 4}},
        )

        action = flow_mod.instructions[0].actions[0]
        self.assertEqual(4, action.port)

    def test_builds_rate_limit_rule_with_meter_and_goto(self):
        flow_mod = build_external_flow(
            FakeDatapath(),
            rule_id="rule-3",
            match={"ipv4_src": "10.0.0.2"},
            action="RATE_LIMIT",
            priority=500,
            meter_id=7,
            rate_limit_pps=100,
        )

        self.assertEqual(POLICY_TABLE_ID, flow_mod.table_id)
        self.assertEqual(7, flow_mod.instructions[0].meter_id)
        self.assertEqual(
            FORWARDING_TABLE_ID,
            flow_mod.instructions[1].table_id,
        )

    def test_builds_packet_per_second_drop_meter(self):
        meter_mod = build_rate_limit_meter(FakeDatapath(), 7, 100)

        self.assertEqual(ofproto_v1_3.OFPMC_ADD, meter_mod.command)
        self.assertEqual(ofproto_v1_3.OFPMF_PKTPS, meter_mod.flags)
        self.assertEqual(7, meter_mod.meter_id)
        self.assertEqual(100, meter_mod.bands[0].rate)

    def test_strict_delete_uses_exact_cookie_and_policy_table(self):
        datapath = FakeDatapath()

        flow_mod = build_external_flow_delete(datapath, "rule-1")

        self.assertEqual(ofproto_v1_3.OFPFC_DELETE, flow_mod.command)
        self.assertEqual(POLICY_TABLE_ID, flow_mod.table_id)
        self.assertEqual(
            build_external_flow_cookie("rule-1"),
            flow_mod.cookie,
        )
        self.assertEqual(0xFFFFFFFFFFFFFFFF, flow_mod.cookie_mask)
        self.assertEqual(ofproto_v1_3.OFPP_ANY, flow_mod.out_port)
        self.assertEqual(ofproto_v1_3.OFPG_ANY, flow_mod.out_group)

    def test_delete_is_followed_by_barrier(self):
        datapath = FakeDatapath()

        flow_mods, barrier = delete_external_flow_with_barrier(
            datapath,
            "rule-1",
        )

        self.assertEqual([*flow_mods, barrier], datapath.sent_messages)
        self.assertEqual([1, 2], [message.xid for message in datapath.sent_messages])


if __name__ == "__main__":
    unittest.main()
