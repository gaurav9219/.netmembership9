import { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  return knex.schema.createTable('user_roles', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.uuid('role_id').notNullable().references('id').inTable('roles').onDelete('CASCADE');
    table.uuid('assigned_by').notNullable().references('id').inTable('users');
    table.timestamp('assigned_at').defaultTo(knex.fn.now());
    table.timestamp('expires_at').nullable(); // Optional expiration for temporary role assignments
    table.boolean('is_active').defaultTo(true);

    // Composite unique constraint to prevent duplicate assignments
    table.unique(['user_id', 'role_id'], 'uq_user_roles_user_role');

    // Indexes for performance
    table.index(['user_id'], 'idx_user_roles_user_id');
    table.index(['role_id'], 'idx_user_roles_role_id');
    table.index(['assigned_by'], 'idx_user_roles_assigned_by');
    table.index(['assigned_at'], 'idx_user_roles_assigned_at');
    table.index(['expires_at'], 'idx_user_roles_expires_at');
    table.index(['is_active'], 'idx_user_roles_is_active');
  });
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists('user_roles');
}