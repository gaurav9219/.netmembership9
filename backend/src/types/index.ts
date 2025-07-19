import { Request } from 'express';

// Database Models
export interface User {
  id: string;
  email: string;
  password_hash: string;
  first_name: string;
  last_name: string;
  is_active: boolean;
  email_verified: boolean;
  email_verified_at?: Date;
  failed_login_attempts: number;
  locked_until?: Date;
  last_login_at?: Date;
  last_login_ip?: string;
  created_at: Date;
  updated_at: Date;
}

export interface Role {
  id: string;
  name: string;
  description?: string;
  is_system_role: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  description?: string;
  is_system_permission: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface UserRole {
  id: string;
  user_id: string;
  role_id: string;
  assigned_by: string;
  assigned_at: Date;
  expires_at?: Date;
  is_active: boolean;
}

export interface RolePermission {
  id: string;
  role_id: string;
  permission_id: string;
  granted_by: string;
  granted_at: Date;
}

export interface RefreshToken {
  id: string;
  user_id: string;
  token_hash: string;
  device_info?: string;
  ip_address?: string;
  expires_at: Date;
  is_revoked: boolean;
  revoked_at?: Date;
  last_used_at?: Date;
  created_at: Date;
  updated_at: Date;
}

export interface AuditLog {
  id: string;
  user_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  old_values?: Record<string, any>;
  new_values?: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
  status: 'success' | 'failure' | 'warning';
  failure_reason?: string;
  metadata?: Record<string, any>;
  created_at: Date;
}

// API Request/Response Types
export interface CreateUserRequest {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface UpdateUserRequest {
  first_name?: string;
  last_name?: string;
  email?: string;
  is_active?: boolean;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permission_ids?: string[];
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
}

export interface AssignRoleRequest {
  user_id: string;
  role_id: string;
  expires_at?: Date;
}

export interface CreatePermissionRequest {
  name: string;
  resource: string;
  action: string;
  description?: string;
}

export interface UpdatePermissionRequest {
  name?: string;
  resource?: string;
  action?: string;
  description?: string;
}

// Response Types
export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user: UserResponse;
  expires_in: number;
}

export interface UserResponse {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  is_active: boolean;
  email_verified: boolean;
  last_login_at?: Date;
  created_at: Date;
  roles: RoleResponse[];
  permissions: string[];
}

export interface RoleResponse {
  id: string;
  name: string;
  description?: string;
  is_system_role: boolean;
  created_at: Date;
  permissions?: PermissionResponse[];
}

export interface PermissionResponse {
  id: string;
  name: string;
  resource: string;
  action: string;
  description?: string;
  is_system_permission: boolean;
  created_at: Date;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    total_pages: number;
    has_next: boolean;
    has_prev: boolean;
  };
}

export interface ApiError {
  message: string;
  code: string;
  details?: Record<string, any>;
  timestamp: Date;
}

// Extended Express Request
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    roles: string[];
    permissions: string[];
  };
  audit?: {
    action: string;
    resource_type: string;
    resource_id?: string;
    old_values?: Record<string, any>;
    new_values?: Record<string, any>;
  };
}

// JWT Payload Types
export interface AccessTokenPayload {
  sub: string; // user id
  email: string;
  roles: string[];
  permissions: string[];
  iat: number;
  exp: number;
}

export interface RefreshTokenPayload {
  sub: string; // user id
  token_id: string;
  iat: number;
  exp: number;
}

// Validation Schemas
export interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

// Query Parameters
export interface PaginationQuery {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

export interface UserQuery extends PaginationQuery {
  search?: string;
  is_active?: boolean;
  role?: string;
}

export interface RoleQuery extends PaginationQuery {
  search?: string;
  is_system_role?: boolean;
}

export interface PermissionQuery extends PaginationQuery {
  search?: string;
  resource?: string;
  action?: string;
}

export interface AuditLogQuery extends PaginationQuery {
  user_id?: string;
  action?: string;
  resource_type?: string;
  status?: string;
  start_date?: Date;
  end_date?: Date;
}

// Service Response Types
export interface ServiceResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
}

// Middleware Types
export interface RateLimitInfo {
  limit: number;
  current: number;
  remaining: number;
  resetTime: Date;
}

// Configuration Types
export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  ssl?: boolean;
}

export interface JWTConfig {
  access_secret: string;
  refresh_secret: string;
  access_expires_in: string;
  refresh_expires_in: string;
}

export interface SecurityConfig {
  bcrypt_rounds: number;
  max_login_attempts: number;
  lockout_time: string;
  rate_limit_window_ms: number;
  rate_limit_max_requests: number;
}

// Enums
export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  LOCKED = 'locked',
  PENDING_VERIFICATION = 'pending_verification'
}

export enum AuditAction {
  LOGIN = 'login',
  LOGOUT = 'logout',
  LOGIN_FAILED = 'login_failed',
  PASSWORD_CHANGED = 'password_changed',
  ROLE_ASSIGNED = 'role_assigned',
  ROLE_REVOKED = 'role_revoked',
  PERMISSION_GRANTED = 'permission_granted',
  PERMISSION_REVOKED = 'permission_revoked',
  USER_CREATED = 'user_created',
  USER_UPDATED = 'user_updated',
  USER_DELETED = 'user_deleted',
  ROLE_CREATED = 'role_created',
  ROLE_UPDATED = 'role_updated',
  ROLE_DELETED = 'role_deleted',
  PERMISSION_CREATED = 'permission_created',
  PERMISSION_UPDATED = 'permission_updated',
  PERMISSION_DELETED = 'permission_deleted'
}

export enum ResourceType {
  USER = 'user',
  ROLE = 'role',
  PERMISSION = 'permission',
  AUDIT_LOG = 'audit_log'
}

export enum ActionType {
  CREATE = 'create',
  READ = 'read',
  UPDATE = 'update',
  DELETE = 'delete',
  ASSIGN = 'assign',
  REVOKE = 'revoke'
}