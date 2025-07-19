import { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  return knex.schema.createTable('roles', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.string('name', 100).notNullable().unique();
    table.string('description', 500).nullable();
    table.boolean('is_system_role').defaultTo(false); // System roles cannot be deleted
    table.timestamps(true, true);

    // Indexes
    table.index(['name'], 'idx_roles_name');
    table.index(['is_system_role'], 'idx_roles_is_system');
    table.index(['created_at'], 'idx_roles_created_at');
  });
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists('roles');
}