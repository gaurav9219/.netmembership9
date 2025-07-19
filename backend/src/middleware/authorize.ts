import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types';

/**
 * Check if user has specific permission
 */
export const requirePermission = (resource: string, action: string) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
      return;
    }

    const requiredPermission = `${resource}:${action}`;
    
    if (!req.user.permissions.includes(requiredPermission)) {
      res.status(403).json({
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        required: requiredPermission,
        user_permissions: req.user.permissions
      });
      return;
    }

    next();
  };
};

/**
 * Check if user has any of the specified permissions
 */
export const requireAnyPermission = (permissions: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
      return;
    }

    const hasPermission = permissions.some(permission => 
      req.user!.permissions.includes(permission)
    );

    if (!hasPermission) {
      res.status(403).json({
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        required_any: permissions,
        user_permissions: req.user.permissions
      });
      return;
    }

    next();
  };
};

/**
 * Check if user has all specified permissions
 */
export const requireAllPermissions = (permissions: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
      return;
    }

    const hasAllPermissions = permissions.every(permission => 
      req.user!.permissions.includes(permission)
    );

    if (!hasAllPermissions) {
      const missingPermissions = permissions.filter(permission => 
        !req.user!.permissions.includes(permission)
      );

      res.status(403).json({
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        required_all: permissions,
        missing: missingPermissions,
        user_permissions: req.user.permissions
      });
      return;
    }

    next();
  };
};

/**
 * Check if user has specific role
 */
export const requireRole = (role: string) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
      return;
    }

    if (!req.user.roles.includes(role)) {
      res.status(403).json({
        error: 'Insufficient role',
        code: 'INSUFFICIENT_ROLE',
        required: role,
        user_roles: req.user.roles
      });
      return;
    }

    next();
  };
};

/**
 * Check if user has any of the specified roles
 */
export const requireAnyRole = (roles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
      return;
    }

    const hasRole = roles.some(role => req.user!.roles.includes(role));

    if (!hasRole) {
      res.status(403).json({
        error: 'Insufficient role',
        code: 'INSUFFICIENT_ROLE',
        required_any: roles,
        user_roles: req.user.roles
      });
      return;
    }

    next();
  };
};

/**
 * Check if user is admin (has admin role or user management permissions)
 */
export const requireAdmin = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
    return;
  }

  const isAdmin = req.user.roles.includes('admin') || 
                  req.user.roles.includes('super-admin') ||
                  req.user.permissions.includes('users:create') ||
                  req.user.permissions.includes('roles:create');

  if (!isAdmin) {
    res.status(403).json({
      error: 'Admin access required',
      code: 'ADMIN_REQUIRED',
      user_roles: req.user.roles
    });
    return;
  }

  next();
};

/**
 * Check if user can access their own resource or has admin permissions
 */
export const requireOwnershipOrAdmin = (userIdParam: string = 'id') => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
      return;
    }

    const targetUserId = req.params[userIdParam];
    const currentUserId = req.user.id;

    // Allow if user is accessing their own resource
    if (targetUserId === currentUserId) {
      next();
      return;
    }

    // Allow if user has admin permissions
    const isAdmin = req.user.roles.includes('admin') || 
                    req.user.roles.includes('super-admin') ||
                    req.user.permissions.some(perm => 
                      perm.includes('users:') || perm.includes('admin:')
                    );

    if (!isAdmin) {
      res.status(403).json({
        error: 'Access denied - can only access own resources or need admin permissions',
        code: 'ACCESS_DENIED',
        user_roles: req.user.roles
      });
      return;
    }

    next();
  };
};

/**
 * Resource-based authorization - check if user can perform action on specific resource
 */
export const authorizeResource = (
  resourceType: string,
  action: string,
  getResourceId?: (req: AuthenticatedRequest) => string
) => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
      return;
    }

    const permission = `${resourceType}:${action}`;
    
    // Check if user has the required permission
    if (!req.user.permissions.includes(permission)) {
      res.status(403).json({
        error: 'Insufficient permissions for this resource',
        code: 'RESOURCE_ACCESS_DENIED',
        required: permission,
        resource_type: resourceType,
        action: action
      });
      return;
    }

    // If resource ID getter is provided, set it for audit logging
    if (getResourceId && req.audit) {
      req.audit.resource_id = getResourceId(req);
    }

    next();
  };
};

/**
 * System role protection - prevent modification of system roles/permissions
 */
export const protectSystemResources = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
    return;
  }

  // Only super-admin can modify system resources
  const canModifySystem = req.user.roles.includes('super-admin');

  if (!canModifySystem) {
    // Check if this is a system resource modification attempt
    const isSystemModification = req.body?.is_system_role === true || 
                                req.body?.is_system_permission === true;

    if (isSystemModification) {
      res.status(403).json({
        error: 'Cannot modify system resources',
        code: 'SYSTEM_RESOURCE_PROTECTED'
      });
      return;
    }
  }

  next();
};