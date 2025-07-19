import { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  return knex.schema.createTable('refresh_tokens', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.string('token_hash', 255).notNullable().unique();
    table.string('device_info', 500).nullable(); // User agent, device info
    table.string('ip_address', 45).nullable();
    table.timestamp('expires_at').notNullable();
    table.boolean('is_revoked').defaultTo(false);
    table.timestamp('revoked_at').nullable();
    table.timestamp('last_used_at').nullable();
    table.timestamps(true, true);

    // Indexes for performance and security
    table.index(['user_id'], 'idx_refresh_tokens_user_id');
    table.index(['token_hash'], 'idx_refresh_tokens_token_hash');
    table.index(['expires_at'], 'idx_refresh_tokens_expires_at');
    table.index(['is_revoked'], 'idx_refresh_tokens_is_revoked');
    table.index(['created_at'], 'idx_refresh_tokens_created_at');
  });
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists('refresh_tokens');
}