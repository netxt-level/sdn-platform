from alembic import op


revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_index(
        "uq_security_responses_event_fingerprint_action",
        table_name="security_responses",
        schema="sdn_controller",
    )
    op.create_index(
        "uq_security_responses_event_id_action",
        "security_responses",
        ["source_event_id", "response_action"],
        unique=True,
        schema="sdn_controller",
    )
    op.create_index(
        "ix_security_responses_event_fingerprint_action",
        "security_responses",
        ["source_event_fingerprint", "response_action"],
        unique=False,
        schema="sdn_controller",
    )

    op.drop_index(
        "uq_flow_rules_source_event_fingerprint_action",
        table_name="flow_rules",
        schema="sdn_controller",
    )
    op.create_index(
        "ix_flow_rules_source_event_fingerprint_action",
        "flow_rules",
        ["source_event_fingerprint", "action"],
        unique=False,
        schema="sdn_controller",
    )


def downgrade():
    op.drop_index(
        "ix_flow_rules_source_event_fingerprint_action",
        table_name="flow_rules",
        schema="sdn_controller",
    )
    op.create_index(
        "uq_flow_rules_source_event_fingerprint_action",
        "flow_rules",
        ["source_event_fingerprint", "action"],
        unique=True,
        schema="sdn_controller",
    )

    op.drop_index(
        "ix_security_responses_event_fingerprint_action",
        table_name="security_responses",
        schema="sdn_controller",
    )
    op.drop_index(
        "uq_security_responses_event_id_action",
        table_name="security_responses",
        schema="sdn_controller",
    )
    op.create_index(
        "uq_security_responses_event_fingerprint_action",
        "security_responses",
        ["source_event_fingerprint", "response_action"],
        unique=True,
        schema="sdn_controller",
    )
