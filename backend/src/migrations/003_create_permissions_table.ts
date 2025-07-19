import { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  return knex.schema.createTable('permissions', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.string('name', 100).notNullable().unique();
    table.string('resource', 100).notNullable(); // e.g., 'users', 'roles', 'permissions'
    table.string('action', 50).notNullable(); // e.g., 'create', 'read', 'update', 'delete'
    table.string('description', 500).nullable();
    table.boolean('is_system_permission').defaultTo(false);
    table.timestamps(true, true);

    // Composite unique constraint for resource + action
    table.unique(['resource', 'action'], 'uq_permissions_resource_action');

    // Indexes
    table.index(['name'], 'idx_permissions_name');
    table.index(['resource'], 'idx_permissions_resource');
    table.index(['action'], 'idx_permissions_action');
    table.index(['resource', 'action'], 'idx_permissions_resource_action');
    table.index(['is_system_permission'], 'idx_permissions_is_system');
  });
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists('permissions');
}