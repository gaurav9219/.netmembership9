import { Knex } from 'knex';

export async function seed(knex: Knex): Promise<void> {
  // Clear existing entries
  await knex('role_permissions').del();
  await knex('roles').del();

  // Define system roles
  const roles = [
    {
      name: 'super-admin',
      description: 'Super Administrator with full system access',
      is_system_role: true
    },
    {
      name: 'admin',
      description: 'Administrator with user and role management access',
      is_system_role: true
    },
    {
      name: 'user-manager',
      description: 'User Manager with limited user management access',
      is_system_role: true
    },
    {
      name: 'auditor',
      description: 'Auditor with read-only access to audit logs',
      is_system_role: true
    },
    {
      name: 'user',
      description: 'Standard user with basic profile access',
      is_system_role: true
    }
  ];

  // Insert roles
  const insertedRoles = [];
  for (const role of roles) {
    const [insertedRole] = await knex('roles')
      .insert({
        id: knex.raw('gen_random_uuid()'),
        ...role,
        created_at: new Date(),
        updated_at: new Date()
      })
      .returning('*');
    insertedRoles.push(insertedRole);
  }

  // Get all permissions
  const permissions = await knex('permissions').select('*');

  // Define role-permission mappings
  const rolePermissions = {
    'super-admin': permissions.map(p => p.id), // All permissions

    'admin': permissions
      .filter(p => 
        p.resource === 'users' ||
        p.resource === 'roles' ||
        p.resource === 'permissions' ||
        p.resource === 'dashboard' ||
        p.resource === 'audit-logs' ||
        p.resource === 'profile' ||
        p.resource === 'sessions'
      )
      .map(p => p.id),

    'user-manager': permissions
      .filter(p => 
        (p.resource === 'users' && ['read', 'create', 'update', 'assign', 'revoke'].includes(p.action)) ||
        (p.resource === 'roles' && p.action === 'read') ||
        p.resource === 'profile' ||
        p.resource === 'sessions' ||
        (p.resource === 'dashboard' && p.action === 'read')
      )
      .map(p => p.id),

    'auditor': permissions
      .filter(p => 
        (p.resource === 'audit-logs' && p.action === 'read') ||
        (p.resource === 'users' && p.action === 'read') ||
        (p.resource === 'roles' && p.action === 'read') ||
        p.resource === 'profile' ||
        p.resource === 'sessions' ||
        (p.resource === 'dashboard' && p.action === 'read')
      )
      .map(p => p.id),

    'user': permissions
      .filter(p => 
        p.resource === 'profile' ||
        p.resource === 'sessions'
      )
      .map(p => p.id)
  };

  // Create a super admin user for role assignments
  const [superAdminUser] = await knex('users')
    .insert({
      id: knex.raw('gen_random_uuid()'),
      email: 'system@rbac.local',
      password_hash: '$2a$12$placeholder', // This will be updated later
      first_name: 'System',
      last_name: 'Administrator',
      is_active: true,
      email_verified: true,
      created_at: new Date(),
      updated_at: new Date()
    })
    .returning('*');

  // Assign permissions to roles
  const rolePermissionInserts = [];
  
  for (const role of insertedRoles) {
    const permissionIds = rolePermissions[role.name as keyof typeof rolePermissions] || [];
    
    for (const permissionId of permissionIds) {
      rolePermissionInserts.push({
        id: knex.raw('gen_random_uuid()'),
        role_id: role.id,
        permission_id: permissionId,
        granted_by: superAdminUser.id,
        granted_at: new Date()
      });
    }
  }

  if (rolePermissionInserts.length > 0) {
    await knex('role_permissions').insert(rolePermissionInserts);
  }

  console.log('✅ Created system roles and permissions');
  console.log(`📋 Roles created: ${insertedRoles.map(r => r.name).join(', ')}`);
  console.log(`🔑 Permissions assigned: ${rolePermissionInserts.length} total assignments`);
}