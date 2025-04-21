"""Add email column to User

Revision ID: 19ecf52ce879
Revises: 
Create Date: 2025-04-20 13:01:30.367280

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '19ecf52ce879'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email', sa.String(length=120), nullable=True))
        batch_op.create_unique_constraint('uq_user_email', ['email'])

    # ### end Alembic commands ###



def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint('uq_user_email', type_='unique')
        batch_op.drop_column('email')

    # ### end Alembic commands ###
