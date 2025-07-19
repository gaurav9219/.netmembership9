// User Types
export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  is_active: boolean;
  email_verified: boolean;
  last_login_at?: string;
  created_at: string;
  roles: Role[];
  permissions: string[];
}

export interface Role {
  id: string;
  name: string;
  description?: string;
  is_system_role: boolean;
  created_at: string;
  permissions?: Permission[];
}

export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  description?: string;
  is_system_permission: boolean;
  created_at: string;
}

// Authentication Types
export interface LoginCredentials {
  email: string;
  password: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user: User;
  expires_in: number;
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  token: string | null;
}

// API Request Types
export interface CreateUserRequest {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
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

export interface AssignRoleRequest {
  user_id: string;
  role_id: string;
  expires_at?: string;
}

// API Response Types
export interface ApiResponse<T> {
  data?: T;
  error?: string;
  code?: string;
  message?: string;
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

// Audit Log Types
export interface AuditLog {
  id: string;
  user_id?: string;
  user_email?: string;
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
  created_at: string;
}

export interface AuditLogQuery extends PaginationQuery {
  user_id?: string;
  action?: string;
  resource_type?: string;
  status?: string;
  start_date?: string;
  end_date?: string;
}

// Session Types
export interface Session {
  id: string;
  device_info?: string;
  ip_address?: string;
  created_at: string;
  last_used_at?: string;
  expires_at: string;
  is_current: boolean;
}

// Form Types
export interface FormField {
  name: string;
  label: string;
  type: 'text' | 'email' | 'password' | 'select' | 'checkbox' | 'textarea';
  required?: boolean;
  placeholder?: string;
  options?: { value: string; label: string }[];
  validation?: any;
}

// UI Component Types
export interface TableColumn<T> {
  key: keyof T | string;
  label: string;
  sortable?: boolean;
  render?: (value: any, row: T) => React.ReactNode;
  width?: string;
}

export interface TableProps<T> {
  data: T[];
  columns: TableColumn<T>[];
  loading?: boolean;
  onSort?: (column: string, direction: 'asc' | 'desc') => void;
  onRowClick?: (row: T) => void;
  pagination?: {
    page: number;
    limit: number;
    total: number;
    onPageChange: (page: number) => void;
    onLimitChange: (limit: number) => void;
  };
}

export interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

export interface ButtonProps {
  variant?: 'primary' | 'secondary' | 'success' | 'warning' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  disabled?: boolean;
  onClick?: () => void;
  type?: 'button' | 'submit' | 'reset';
  children: React.ReactNode;
  className?: string;
}

export interface AlertProps {
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
  onClose?: () => void;
  autoClose?: boolean;
  duration?: number;
}

// Navigation Types
export interface NavItem {
  label: string;
  href: string;
  icon?: React.ComponentType<any>;
  permissions?: string[];
  children?: NavItem[];
}

// Dashboard Types
export interface DashboardStats {
  total_users: number;
  active_users: number;
  total_roles: number;
  total_permissions: number;
  recent_logins: number;
  failed_logins: number;
}

export interface SecuritySummary {
  period_days: number;
  failed_login_attempts: number;
  successful_logins: number;
  password_changes: number;
  role_assignments: number;
  suspicious_ips: Array<{
    ip_address: string;
    failed_attempts: number;
  }>;
}

// Error Types
export interface ApiError {
  message: string;
  code: string;
  details?: Record<string, any>;
  timestamp: string;
}

export interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

// Utility Types
export type Permission = string; // Format: "resource:action"

export interface HasPermission {
  (permission: Permission): boolean;
}

export interface HasRole {
  (role: string): boolean;
}

export interface HasAnyPermission {
  (permissions: Permission[]): boolean;
}

export interface HasAllPermissions {
  (permissions: Permission[]): boolean;
}

// Route Types
export interface ProtectedRouteProps {
  children: React.ReactNode;
  permissions?: Permission[];
  roles?: string[];
  requireAll?: boolean;
  fallback?: React.ReactNode;
}

// Theme Types
export interface Theme {
  colors: {
    primary: string;
    secondary: string;
    success: string;
    warning: string;
    danger: string;
    background: string;
    surface: string;
    text: string;
  };
  spacing: {
    xs: string;
    sm: string;
    md: string;
    lg: string;
    xl: string;
  };
  borderRadius: {
    sm: string;
    md: string;
    lg: string;
  };
}

// Context Types
export interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<void>;
  hasPermission: HasPermission;
  hasRole: HasRole;
  hasAnyPermission: HasAnyPermission;
  hasAllPermissions: HasAllPermissions;
}

export interface AppContextType {
  theme: Theme;
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  notifications: Notification[];
  addNotification: (notification: Omit<Notification, 'id'>) => void;
  removeNotification: (id: string) => void;
}

export interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
  duration?: number;
  actions?: Array<{
    label: string;
    onClick: () => void;
  }>;
}