from alembic import op
import sqlalchemy as sa


revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "platform_settings",
        sa.Column("id", sa.String(length=30), nullable=False),
        sa.Column(
            "congestion_threshold_percent",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("70"),
        ),
        sa.Column(
            "automatic_response_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sdn_controller",
    )
    op.execute(
        "INSERT INTO sdn_controller.platform_settings "
        "(id, congestion_threshold_percent, automatic_response_enabled) "
        "VALUES ('default', 70, true)"
    )


def downgrade():
    op.drop_table("platform_settings", schema="sdn_controller")
