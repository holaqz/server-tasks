"""add_soft_delete_fields_to_roles

Revision ID: 98854cd6e2a6
Revises: 8f4d8135fa19
Create Date: 2024-03-19 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '98854cd6e2a6'
down_revision: Union[str, None] = '8f4d8135fa19'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Create new table
    op.create_table('roles_new',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.String(length=255)),
        sa.Column('code', sa.String(length=100), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)')),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('deleted_by', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code'),
        sa.UniqueConstraint('name'),
        sa.ForeignKeyConstraint(['deleted_by'], ['users.id'], ondelete='SET NULL')
    )
    
    # Copy data
    op.execute('INSERT INTO roles_new (id, name, description, code, is_deleted, created_at, updated_at) '
               'SELECT id, name, description, code, is_deleted, created_at, updated_at FROM roles')
    
    # Drop old table
    op.drop_table('roles')
    
    # Rename new table to old name
    op.rename_table('roles_new', 'roles')

def downgrade() -> None:
    # Create old table structure
    op.create_table('roles_old',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.String(length=255)),
        sa.Column('code', sa.String(length=100), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)')),
        sa.Column('updated_at', sa.DateTime()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code'),
        sa.UniqueConstraint('name')
    )
    
    # Copy data back
    op.execute('INSERT INTO roles_old (id, name, description, code, is_deleted, created_at, updated_at) '
               'SELECT id, name, description, code, is_deleted, created_at, updated_at FROM roles')
    
    # Drop new table
    op.drop_table('roles')
    
    # Rename old table back
    op.rename_table('roles_old', 'roles')
