from alembic import op
import sqlalchemy as sa


revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "flow_rules",
        sa.Column(
            "removed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        schema="sdn_controller",
    )


def downgrade():
    op.drop_column(
        "flow_rules",
        "removed_at",
        schema="sdn_controller",
    )
