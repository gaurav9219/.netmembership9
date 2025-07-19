import { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  return knex.schema.createTable('users', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.string('email', 255).notNullable().unique();
    table.string('password_hash', 255).notNullable();
    table.string('first_name', 100).notNullable();
    table.string('last_name', 100).notNullable();
    table.boolean('is_active').defaultTo(true);
    table.boolean('email_verified').defaultTo(false);
    table.timestamp('email_verified_at').nullable();
    table.integer('failed_login_attempts').defaultTo(0);
    table.timestamp('locked_until').nullable();
    table.timestamp('last_login_at').nullable();
    table.string('last_login_ip', 45).nullable(); // IPv6 support
    table.timestamps(true, true);

    // Indexes for performance
    table.index(['email'], 'idx_users_email');
    table.index(['is_active'], 'idx_users_is_active');
    table.index(['created_at'], 'idx_users_created_at');
    table.index(['email_verified'], 'idx_users_email_verified');
  });
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists('users');
}