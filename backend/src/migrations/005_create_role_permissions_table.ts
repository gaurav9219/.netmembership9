import { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  return knex.schema.createTable('role_permissions', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.uuid('role_id').notNullable().references('id').inTable('roles').onDelete('CASCADE');
    table.uuid('permission_id').notNullable().references('id').inTable('permissions').onDelete('CASCADE');
    table.uuid('granted_by').notNullable().references('id').inTable('users');
    table.timestamp('granted_at').defaultTo(knex.fn.now());

    // Composite unique constraint to prevent duplicate permissions
    table.unique(['role_id', 'permission_id'], 'uq_role_permissions_role_permission');

    // Indexes for performance
    table.index(['role_id'], 'idx_role_permissions_role_id');
    table.index(['permission_id'], 'idx_role_permissions_permission_id');
    table.index(['granted_by'], 'idx_role_permissions_granted_by');
    table.index(['granted_at'], 'idx_role_permissions_granted_at');
  });
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists('role_permissions');
}