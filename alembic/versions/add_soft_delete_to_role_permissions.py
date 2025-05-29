"""add_soft_delete_to_role_permissions

Revision ID: 2024_03_20_soft_delete_role_perm
Revises: ff9b1fef6cf0
Create Date: 2024-03-20 10:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '2024_03_20_soft_delete_role_perm'
down_revision: Union[str, None] = 'ff9b1fef6cf0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Create new table
    op.create_table('roles_and_permissions_new',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('permission_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)')),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('is_deleted', sa.Boolean(), default=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('deleted_by', sa.Integer(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('role_id', 'permission_id', name='_role_permission_uc'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['deleted_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL')
    )
    
    # Copy data
    op.execute('INSERT INTO roles_and_permissions_new (id, role_id, permission_id, created_at, updated_at) '
               'SELECT id, role_id, permission_id, created_at, updated_at FROM roles_and_permissions')
    
    # Drop old table
    op.drop_table('roles_and_permissions')
    
    # Rename new table to old name
    op.rename_table('roles_and_permissions_new', 'roles_and_permissions')

def downgrade() -> None:
    # Create old table structure
    op.create_table('roles_and_permissions_old',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('permission_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)')),
        sa.Column('updated_at', sa.DateTime()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('role_id', 'permission_id', name='_role_permission_uc'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], ondelete='CASCADE')
    )
    
    # Copy data back
    op.execute('INSERT INTO roles_and_permissions_old (id, role_id, permission_id, created_at, updated_at) '
               'SELECT id, role_id, permission_id, created_at, updated_at FROM roles_and_permissions')
    
    # Drop new table
    op.drop_table('roles_and_permissions')
    
    # Rename old table back
    op.rename_table('roles_and_permissions_old', 'roles_and_permissions') 