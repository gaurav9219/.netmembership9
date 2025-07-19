import { Knex } from 'knex';

export async function seed(knex: Knex): Promise<void> {
  // Clear existing entries
  await knex('permissions').del();

  // Define system permissions
  const permissions = [
    // User management permissions
    { name: 'Create Users', resource: 'users', action: 'create', description: 'Create new user accounts', is_system_permission: true },
    { name: 'Read Users', resource: 'users', action: 'read', description: 'View user information and lists', is_system_permission: true },
    { name: 'Update Users', resource: 'users', action: 'update', description: 'Modify user information', is_system_permission: true },
    { name: 'Delete Users', resource: 'users', action: 'delete', description: 'Delete user accounts', is_system_permission: true },
    { name: 'Assign User Roles', resource: 'users', action: 'assign', description: 'Assign roles to users', is_system_permission: true },
    { name: 'Revoke User Roles', resource: 'users', action: 'revoke', description: 'Remove roles from users', is_system_permission: true },

    // Role management permissions
    { name: 'Create Roles', resource: 'roles', action: 'create', description: 'Create new roles', is_system_permission: true },
    { name: 'Read Roles', resource: 'roles', action: 'read', description: 'View role information and lists', is_system_permission: true },
    { name: 'Update Roles', resource: 'roles', action: 'update', description: 'Modify role information', is_system_permission: true },
    { name: 'Delete Roles', resource: 'roles', action: 'delete', description: 'Delete roles', is_system_permission: true },
    { name: 'Assign Role Permissions', resource: 'roles', action: 'assign', description: 'Assign permissions to roles', is_system_permission: true },
    { name: 'Revoke Role Permissions', resource: 'roles', action: 'revoke', description: 'Remove permissions from roles', is_system_permission: true },

    // Permission management permissions
    { name: 'Create Permissions', resource: 'permissions', action: 'create', description: 'Create new permissions', is_system_permission: true },
    { name: 'Read Permissions', resource: 'permissions', action: 'read', description: 'View permission information and lists', is_system_permission: true },
    { name: 'Update Permissions', resource: 'permissions', action: 'update', description: 'Modify permission information', is_system_permission: true },
    { name: 'Delete Permissions', resource: 'permissions', action: 'delete', description: 'Delete permissions', is_system_permission: true },

    // Audit log permissions
    { name: 'Read Audit Logs', resource: 'audit-logs', action: 'read', description: 'View audit logs and security events', is_system_permission: true },
    { name: 'Delete Audit Logs', resource: 'audit-logs', action: 'delete', description: 'Delete old audit logs', is_system_permission: true },

    // System administration permissions
    { name: 'System Admin', resource: 'system', action: 'admin', description: 'Full system administration access', is_system_permission: true },
    { name: 'View Dashboard', resource: 'dashboard', action: 'read', description: 'Access admin dashboard', is_system_permission: true },
    { name: 'Manage Settings', resource: 'settings', action: 'update', description: 'Modify system settings', is_system_permission: true },

    // Profile management (self-service permissions)
    { name: 'Read Own Profile', resource: 'profile', action: 'read', description: 'View own user profile', is_system_permission: false },
    { name: 'Update Own Profile', resource: 'profile', action: 'update', description: 'Modify own user profile', is_system_permission: false },
    { name: 'Change Own Password', resource: 'profile', action: 'password', description: 'Change own password', is_system_permission: false },

    // Session management
    { name: 'Manage Own Sessions', resource: 'sessions', action: 'manage', description: 'View and revoke own sessions', is_system_permission: false },
  ];

  // Insert permissions with UUIDs
  const permissionsWithIds = permissions.map(permission => ({
    id: knex.raw('gen_random_uuid()'),
    ...permission,
    created_at: new Date(),
    updated_at: new Date()
  }));

  await knex('permissions').insert(permissionsWithIds);
}