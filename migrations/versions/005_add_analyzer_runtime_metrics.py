from alembic import op
import sqlalchemy as sa


revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "analyzer",
        sa.Column(
            "pending_security_event_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        schema="sdn_controller",
    )
    op.add_column(
        "analyzer",
        sa.Column(
            "dropped_security_event_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        schema="sdn_controller",
    )
    op.add_column(
        "analyzer",
        sa.Column(
            "packet_buffer_dropped_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        schema="sdn_controller",
    )
    op.add_column(
        "analyzer",
        sa.Column(
            "last_security_event_send_failure",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        schema="sdn_controller",
    )


def downgrade():
    op.drop_column(
        "analyzer",
        "last_security_event_send_failure",
        schema="sdn_controller",
    )
    op.drop_column(
        "analyzer",
        "packet_buffer_dropped_count",
        schema="sdn_controller",
    )
    op.drop_column(
        "analyzer",
        "dropped_security_event_count",
        schema="sdn_controller",
    )
    op.drop_column(
        "analyzer",
        "pending_security_event_count",
        schema="sdn_controller",
    )
