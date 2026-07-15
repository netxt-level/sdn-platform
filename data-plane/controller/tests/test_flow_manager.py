import unittest

from os_ken.ofproto import ofproto_v1_3
from os_ken.ofproto import ofproto_v1_3_parser

from app.flow_manager import TABLE_MISS_COOKIE
from app.flow_manager import TABLE_MISS_PRIORITY
from app.flow_manager import TABLE_MISS_TABLE_ID
from app.flow_manager import install_table_miss_flow


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


if __name__ == "__main__":
    unittest.main()
