"""add_soft_delete_fields_v4

Revision ID: add_soft_delete_fields_4
Revises: ca551b1cd312
Create Date: 2024-03-19 15:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'add_soft_delete_fields_4'
down_revision: Union[str, None] = 'ca551b1cd312'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Создаем временную таблицу
    op.create_table('users_and_roles_new',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('deleted_by', sa.Integer(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_users_and_roles_user_id_users', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name='fk_users_and_roles_role_id_roles', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['deleted_by'], ['users.id'], name='fk_users_and_roles_deleted_by_users', ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], name='fk_users_and_roles_created_by_users', ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'role_id', name='_user_role_uc')
    )
    
    # Копируем данные
    op.execute('''
        INSERT INTO users_and_roles_new (id, user_id, role_id, created_at, updated_at)
        SELECT id, user_id, role_id, created_at, updated_at
        FROM users_and_roles
    ''')
    
    # Удаляем старую таблицу
    op.drop_table('users_and_roles')
    
    # Переименовываем новую таблицу
    op.rename_table('users_and_roles_new', 'users_and_roles')

def downgrade() -> None:
    # Создаем временную таблицу без новых полей
    op.create_table('users_and_roles_old',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_users_and_roles_user_id_users', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name='fk_users_and_roles_role_id_roles', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'role_id', name='_user_role_uc')
    )
    
    # Копируем данные обратно
    op.execute('''
        INSERT INTO users_and_roles_old (id, user_id, role_id, created_at, updated_at)
        SELECT id, user_id, role_id, created_at, updated_at
        FROM users_and_roles
    ''')
    
    # Удаляем новую таблицу
    op.drop_table('users_and_roles')
    
    # Переименовываем старую таблицу
    op.rename_table('users_and_roles_old', 'users_and_roles') 