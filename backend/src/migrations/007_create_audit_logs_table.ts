import { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  return knex.schema.createTable('audit_logs', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.uuid('user_id').nullable().references('id').inTable('users').onDelete('SET NULL');
    table.string('action', 100).notNullable(); // e.g., 'login', 'role_assigned', 'permission_granted'
    table.string('resource_type', 50).notNullable(); // e.g., 'user', 'role', 'permission'
    table.uuid('resource_id').nullable(); // ID of the affected resource
    table.json('old_values').nullable(); // Previous state
    table.json('new_values').nullable(); // New state
    table.string('ip_address', 45).nullable();
    table.string('user_agent', 1000).nullable();
    table.string('status', 20).notNullable(); // 'success', 'failure', 'warning'
    table.string('failure_reason', 500).nullable();
    table.json('metadata').nullable(); // Additional context
    table.timestamp('created_at').defaultTo(knex.fn.now());

    // Indexes for querying and performance
    table.index(['user_id'], 'idx_audit_logs_user_id');
    table.index(['action'], 'idx_audit_logs_action');
    table.index(['resource_type'], 'idx_audit_logs_resource_type');
    table.index(['resource_id'], 'idx_audit_logs_resource_id');
    table.index(['status'], 'idx_audit_logs_status');
    table.index(['created_at'], 'idx_audit_logs_created_at');
    table.index(['user_id', 'created_at'], 'idx_audit_logs_user_created');
  });
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists('audit_logs');
}