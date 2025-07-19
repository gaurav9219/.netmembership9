import db from '../config/database';
import { hashPassword, comparePassword } from '../utils/password';
import { 
  User, 
  Role, 
  Permission, 
  CreateUserRequest, 
  UpdateUserRequest,
  UserResponse,
  RoleResponse,
  PermissionResponse,
  PaginatedResponse,
  UserQuery,
  ServiceResult
} from '../types';
import { AuditService } from './AuditService';

export class UserService {
  private auditService: AuditService;

  constructor() {
    this.auditService = new AuditService();
  }

  /**
   * Create a new user
   */
  async createUser(userData: CreateUserRequest, createdBy?: string): Promise<ServiceResult<UserResponse>> {
    const trx = await db.transaction();
    
    try {
      // Check if email already exists
      const existingUser = await trx('users')
        .where('email', userData.email)
        .first();

      if (existingUser) {
        await trx.rollback();
        return {
          success: false,
          error: 'Email already exists',
          code: 'EMAIL_EXISTS'
        };
      }

      // Hash password
      const passwordHash = await hashPassword(userData.password);

      // Create user
      const [user] = await trx('users')
        .insert({
          email: userData.email,
          password_hash: passwordHash,
          first_name: userData.first_name,
          last_name: userData.last_name,
          is_active: true,
          email_verified: false,
          failed_login_attempts: 0
        })
        .returning('*');

      // Assign default role if exists
      const defaultRole = await trx('roles')
        .where('name', 'user')
        .first();

      if (defaultRole && createdBy) {
        await trx('user_roles')
          .insert({
            user_id: user.id,
            role_id: defaultRole.id,
            assigned_by: createdBy
          });
      }

      await trx.commit();

      // Log audit event
      if (createdBy) {
        await this.auditService.log({
          user_id: createdBy,
          action: 'user_created',
          resource_type: 'user',
          resource_id: user.id,
          new_values: {
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name
          },
          status: 'success'
        });
      }

      const userResponse = await this.getUserResponse(user);
      return {
        success: true,
        data: userResponse
      };

    } catch (error) {
      await trx.rollback();
      console.error('Error creating user:', error);
      return {
        success: false,
        error: 'Failed to create user',
        code: 'CREATE_USER_ERROR'
      };
    }
  }

  /**
   * Find user by ID
   */
  async findById(id: string): Promise<User | null> {
    try {
      const user = await db('users')
        .where('id', id)
        .first();

      return user || null;
    } catch (error) {
      console.error('Error finding user by ID:', error);
      return null;
    }
  }

  /**
   * Find user by email
   */
  async findByEmail(email: string): Promise<User | null> {
    try {
      const user = await db('users')
        .where('email', email)
        .first();

      return user || null;
    } catch (error) {
      console.error('Error finding user by email:', error);
      return null;
    }
  }

  /**
   * Update user
   */
  async updateUser(id: string, userData: UpdateUserRequest, updatedBy: string): Promise<ServiceResult<UserResponse>> {
    const trx = await db.transaction();
    
    try {
      // Get current user data for audit
      const currentUser = await trx('users')
        .where('id', id)
        .first();

      if (!currentUser) {
        await trx.rollback();
        return {
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        };
      }

      // Check if email already exists (if changing email)
      if (userData.email && userData.email !== currentUser.email) {
        const existingUser = await trx('users')
          .where('email', userData.email)
          .whereNot('id', id)
          .first();

        if (existingUser) {
          await trx.rollback();
          return {
            success: false,
            error: 'Email already exists',
            code: 'EMAIL_EXISTS'
          };
        }
      }

      // Update user
      const [updatedUser] = await trx('users')
        .where('id', id)
        .update({
          ...userData,
          updated_at: new Date()
        })
        .returning('*');

      await trx.commit();

      // Log audit event
      await this.auditService.log({
        user_id: updatedBy,
        action: 'user_updated',
        resource_type: 'user',
        resource_id: id,
        old_values: {
          email: currentUser.email,
          first_name: currentUser.first_name,
          last_name: currentUser.last_name,
          is_active: currentUser.is_active
        },
        new_values: userData,
        status: 'success'
      });

      const userResponse = await this.getUserResponse(updatedUser);
      return {
        success: true,
        data: userResponse
      };

    } catch (error) {
      await trx.rollback();
      console.error('Error updating user:', error);
      return {
        success: false,
        error: 'Failed to update user',
        code: 'UPDATE_USER_ERROR'
      };
    }
  }

  /**
   * Change user password
   */
  async changePassword(id: string, currentPassword: string, newPassword: string): Promise<ServiceResult<boolean>> {
    const trx = await db.transaction();
    
    try {
      const user = await trx('users')
        .where('id', id)
        .first();

      if (!user) {
        await trx.rollback();
        return {
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        };
      }

      // Verify current password
      const isCurrentPasswordValid = await comparePassword(currentPassword, user.password_hash);
      if (!isCurrentPasswordValid) {
        await trx.rollback();
        return {
          success: false,
          error: 'Current password is incorrect',
          code: 'INVALID_CURRENT_PASSWORD'
        };
      }

      // Hash new password
      const newPasswordHash = await hashPassword(newPassword);

      // Update password
      await trx('users')
        .where('id', id)
        .update({
          password_hash: newPasswordHash,
          updated_at: new Date()
        });

      // Revoke all refresh tokens to force re-login
      await trx('refresh_tokens')
        .where('user_id', id)
        .update({
          is_revoked: true,
          revoked_at: new Date()
        });

      await trx.commit();

      // Log audit event
      await this.auditService.log({
        user_id: id,
        action: 'password_changed',
        resource_type: 'user',
        resource_id: id,
        status: 'success'
      });

      return {
        success: true,
        data: true
      };

    } catch (error) {
      await trx.rollback();
      console.error('Error changing password:', error);
      return {
        success: false,
        error: 'Failed to change password',
        code: 'CHANGE_PASSWORD_ERROR'
      };
    }
  }

  /**
   * Get users with pagination and filtering
   */
  async getUsers(query: UserQuery): Promise<PaginatedResponse<UserResponse>> {
    try {
      const { page = 1, limit = 10, search, is_active, role, sort = 'created_at', order = 'desc' } = query;
      const offset = (page - 1) * limit;

      let baseQuery = db('users')
        .select('users.*')
        .leftJoin('user_roles', 'users.id', 'user_roles.user_id')
        .leftJoin('roles', 'user_roles.role_id', 'roles.id')
        .groupBy('users.id');

      // Apply filters
      if (search) {
        baseQuery = baseQuery.where(function() {
          this.where('users.email', 'ilike', `%${search}%`)
              .orWhere('users.first_name', 'ilike', `%${search}%`)
              .orWhere('users.last_name', 'ilike', `%${search}%`);
        });
      }

      if (typeof is_active === 'boolean') {
        baseQuery = baseQuery.where('users.is_active', is_active);
      }

      if (role) {
        baseQuery = baseQuery.where('roles.id', role);
      }

      // Get total count
      const countResult = await baseQuery.clone().count('users.id as count').first();
      const total = parseInt(countResult?.count as string) || 0;

      // Get users with pagination
      const users = await baseQuery
        .orderBy(`users.${sort}`, order)
        .limit(limit)
        .offset(offset);

      // Convert to user responses
      const userResponses = await Promise.all(
        users.map(user => this.getUserResponse(user))
      );

      return {
        data: userResponses,
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.ceil(total / limit),
          has_next: page < Math.ceil(total / limit),
          has_prev: page > 1
        }
      };

    } catch (error) {
      console.error('Error getting users:', error);
      return {
        data: [],
        pagination: {
          page: 1,
          limit: 10,
          total: 0,
          total_pages: 0,
          has_next: false,
          has_prev: false
        }
      };
    }
  }

  /**
   * Get user roles
   */
  async getUserRoles(userId: string): Promise<Role[]> {
    try {
      const roles = await db('roles')
        .join('user_roles', 'roles.id', 'user_roles.role_id')
        .where('user_roles.user_id', userId)
        .where('user_roles.is_active', true)
        .where(function() {
          this.whereNull('user_roles.expires_at')
              .orWhere('user_roles.expires_at', '>', new Date());
        })
        .select('roles.*');

      return roles;
    } catch (error) {
      console.error('Error getting user roles:', error);
      return [];
    }
  }

  /**
   * Get user permissions
   */
  async getUserPermissions(userId: string): Promise<Permission[]> {
    try {
      const permissions = await db('permissions')
        .join('role_permissions', 'permissions.id', 'role_permissions.permission_id')
        .join('user_roles', 'role_permissions.role_id', 'user_roles.role_id')
        .where('user_roles.user_id', userId)
        .where('user_roles.is_active', true)
        .where(function() {
          this.whereNull('user_roles.expires_at')
              .orWhere('user_roles.expires_at', '>', new Date());
        })
        .select('permissions.*')
        .groupBy('permissions.id');

      return permissions;
    } catch (error) {
      console.error('Error getting user permissions:', error);
      return [];
    }
  }

  /**
   * Assign role to user
   */
  async assignRole(userId: string, roleId: string, assignedBy: string, expiresAt?: Date): Promise<ServiceResult<boolean>> {
    const trx = await db.transaction();
    
    try {
      // Check if user exists
      const user = await trx('users').where('id', userId).first();
      if (!user) {
        await trx.rollback();
        return {
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        };
      }

      // Check if role exists
      const role = await trx('roles').where('id', roleId).first();
      if (!role) {
        await trx.rollback();
        return {
          success: false,
          error: 'Role not found',
          code: 'ROLE_NOT_FOUND'
        };
      }

      // Check if assignment already exists
      const existingAssignment = await trx('user_roles')
        .where('user_id', userId)
        .where('role_id', roleId)
        .first();

      if (existingAssignment) {
        await trx.rollback();
        return {
          success: false,
          error: 'Role already assigned to user',
          code: 'ROLE_ALREADY_ASSIGNED'
        };
      }

      // Create assignment
      await trx('user_roles').insert({
        user_id: userId,
        role_id: roleId,
        assigned_by: assignedBy,
        expires_at: expiresAt
      });

      await trx.commit();

      // Log audit event
      await this.auditService.log({
        user_id: assignedBy,
        action: 'role_assigned',
        resource_type: 'user',
        resource_id: userId,
        new_values: {
          role_id: roleId,
          role_name: role.name,
          expires_at: expiresAt
        },
        status: 'success'
      });

      return {
        success: true,
        data: true
      };

    } catch (error) {
      await trx.rollback();
      console.error('Error assigning role:', error);
      return {
        success: false,
        error: 'Failed to assign role',
        code: 'ASSIGN_ROLE_ERROR'
      };
    }
  }

  /**
   * Revoke role from user
   */
  async revokeRole(userId: string, roleId: string, revokedBy: string): Promise<ServiceResult<boolean>> {
    const trx = await db.transaction();
    
    try {
      // Check if assignment exists
      const assignment = await trx('user_roles')
        .where('user_id', userId)
        .where('role_id', roleId)
        .first();

      if (!assignment) {
        await trx.rollback();
        return {
          success: false,
          error: 'Role assignment not found',
          code: 'ASSIGNMENT_NOT_FOUND'
        };
      }

      // Get role details for audit
      const role = await trx('roles').where('id', roleId).first();

      // Remove assignment
      await trx('user_roles')
        .where('user_id', userId)
        .where('role_id', roleId)
        .del();

      await trx.commit();

      // Log audit event
      await this.auditService.log({
        user_id: revokedBy,
        action: 'role_revoked',
        resource_type: 'user',
        resource_id: userId,
        old_values: {
          role_id: roleId,
          role_name: role?.name
        },
        status: 'success'
      });

      return {
        success: true,
        data: true
      };

    } catch (error) {
      await trx.rollback();
      console.error('Error revoking role:', error);
      return {
        success: false,
        error: 'Failed to revoke role',
        code: 'REVOKE_ROLE_ERROR'
      };
    }
  }

  /**
   * Handle failed login attempt
   */
  async handleFailedLogin(email: string, ipAddress?: string): Promise<void> {
    const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5');
    const lockoutTime = process.env.LOCKOUT_TIME || '15m';
    
    try {
      const user = await db('users').where('email', email).first();
      if (!user) return;

      const newAttempts = user.failed_login_attempts + 1;
      let lockedUntil = null;

      if (newAttempts >= maxAttempts) {
        // Calculate lockout time
        const lockoutMs = this.parseLockoutTime(lockoutTime);
        lockedUntil = new Date(Date.now() + lockoutMs);
      }

      await db('users')
        .where('id', user.id)
        .update({
          failed_login_attempts: newAttempts,
          locked_until: lockedUntil
        });

      // Log audit event
      await this.auditService.log({
        user_id: user.id,
        action: 'login_failed',
        resource_type: 'user',
        resource_id: user.id,
        ip_address: ipAddress,
        status: 'failure',
        failure_reason: newAttempts >= maxAttempts ? 'Account locked due to multiple failed attempts' : 'Invalid credentials'
      });

    } catch (error) {
      console.error('Error handling failed login:', error);
    }
  }

  /**
   * Handle successful login
   */
  async handleSuccessfulLogin(userId: string, ipAddress?: string): Promise<void> {
    try {
      await db('users')
        .where('id', userId)
        .update({
          failed_login_attempts: 0,
          locked_until: null,
          last_login_at: new Date(),
          last_login_ip: ipAddress
        });

      // Log audit event
      await this.auditService.log({
        user_id: userId,
        action: 'login',
        resource_type: 'user',
        resource_id: userId,
        ip_address: ipAddress,
        status: 'success'
      });

    } catch (error) {
      console.error('Error handling successful login:', error);
    }
  }

  /**
   * Convert user to response format
   */
  private async getUserResponse(user: User): Promise<UserResponse> {
    const roles = await this.getUserRoles(user.id);
    const permissions = await this.getUserPermissions(user.id);

    return {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      is_active: user.is_active,
      email_verified: user.email_verified,
      last_login_at: user.last_login_at,
      created_at: user.created_at,
      roles: roles.map(role => ({
        id: role.id,
        name: role.name,
        description: role.description,
        is_system_role: role.is_system_role,
        created_at: role.created_at
      })),
      permissions: permissions.map(permission => `${permission.resource}:${permission.action}`)
    };
  }

  /**
   * Parse lockout time string to milliseconds
   */
  private parseLockoutTime(lockoutTime: string): number {
    const match = lockoutTime.match(/^(\d+)([smhd])$/);
    if (!match) return 15 * 60 * 1000; // Default 15 minutes

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default: return 15 * 60 * 1000;
    }
  }
}