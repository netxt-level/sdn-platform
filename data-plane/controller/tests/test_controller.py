import unittest
from types import SimpleNamespace

from os_ken.ofproto import ofproto_v1_3

from app.controller import SwitchConnectionController


class PortStatusTests(unittest.TestCase):
    @staticmethod
    def message(reason, config=0, state=0):
        return SimpleNamespace(
            reason=reason,
            datapath=SimpleNamespace(ofproto=ofproto_v1_3),
            desc=SimpleNamespace(config=config, state=state),
        )

    def test_add_or_modify_with_live_port_is_active(self):
        for reason in (
            ofproto_v1_3.OFPPR_ADD,
            ofproto_v1_3.OFPPR_MODIFY,
        ):
            with self.subTest(reason=reason):
                self.assertTrue(
                    SwitchConnectionController._port_is_active(
                        self.message(reason),
                    )
                )

    def test_deleted_port_is_inactive(self):
        self.assertFalse(
            SwitchConnectionController._port_is_active(
                self.message(ofproto_v1_3.OFPPR_DELETE),
            )
        )

    def test_configured_down_port_is_inactive(self):
        self.assertFalse(
            SwitchConnectionController._port_is_active(
                self.message(
                    ofproto_v1_3.OFPPR_MODIFY,
                    config=ofproto_v1_3.OFPPC_PORT_DOWN,
                ),
            )
        )

    def test_link_down_or_blocked_port_is_inactive(self):
        for state in (
            ofproto_v1_3.OFPPS_LINK_DOWN,
            ofproto_v1_3.OFPPS_BLOCKED,
        ):
            with self.subTest(state=state):
                self.assertFalse(
                    SwitchConnectionController._port_is_active(
                        self.message(
                            ofproto_v1_3.OFPPR_MODIFY,
                            state=state,
                        ),
                    )
                )

    def test_unknown_reason_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown port status reason"):
            SwitchConnectionController._port_is_active(self.message(99))

    def test_port_description_uses_current_config_and_state(self):
        datapath = SimpleNamespace(ofproto=ofproto_v1_3)
        active = SimpleNamespace(config=0, state=0)
        configured_down = SimpleNamespace(
            config=ofproto_v1_3.OFPPC_PORT_DOWN,
            state=0,
        )
        link_down = SimpleNamespace(
            config=0,
            state=ofproto_v1_3.OFPPS_LINK_DOWN,
        )

        self.assertTrue(
            SwitchConnectionController._port_description_is_active(
                datapath,
                active,
            )
        )
        self.assertFalse(
            SwitchConnectionController._port_description_is_active(
                datapath,
                configured_down,
            )
        )
        self.assertFalse(
            SwitchConnectionController._port_description_is_active(
                datapath,
                link_down,
            )
        )


if __name__ == "__main__":
    unittest.main()
