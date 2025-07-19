import { Response, NextFunction } from 'express';
import { verifyAccessToken } from '../config/jwt';
import { AuthenticatedRequest } from '../types';
import { UserService } from '../services/UserService';

/**
 * Authentication middleware - verifies JWT token and loads user context
 */
export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'Access token required',
        code: 'MISSING_TOKEN'
      });
      return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix
    
    // Verify the token
    const payload = verifyAccessToken(token);
    
    // Load user details with current roles and permissions
    const userService = new UserService();
    const user = await userService.findById(payload.sub);
    
    if (!user) {
      res.status(401).json({
        error: 'Invalid token - user not found',
        code: 'USER_NOT_FOUND'
      });
      return;
    }

    if (!user.is_active) {
      res.status(401).json({
        error: 'Account is deactivated',
        code: 'ACCOUNT_DEACTIVATED'
      });
      return;
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      res.status(401).json({
        error: 'Account is temporarily locked',
        code: 'ACCOUNT_LOCKED',
        locked_until: user.locked_until
      });
      return;
    }

    // Get user's current roles and permissions
    const userRoles = await userService.getUserRoles(user.id);
    const userPermissions = await userService.getUserPermissions(user.id);

    // Set user context on request
    req.user = {
      id: user.id,
      email: user.email,
      roles: userRoles.map(role => role.name),
      permissions: userPermissions.map(permission => `${permission.resource}:${permission.action}`)
    };

    next();
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('expired')) {
        res.status(401).json({
          error: 'Token expired',
          code: 'TOKEN_EXPIRED'
        });
        return;
      }
      
      if (error.message.includes('Invalid')) {
        res.status(401).json({
          error: 'Invalid token',
          code: 'INVALID_TOKEN'
        });
        return;
      }
    }

    console.error('Authentication error:', error);
    res.status(500).json({
      error: 'Authentication failed',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * Optional authentication middleware - doesn't fail if no token provided
 */
export const optionalAuth = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    next();
    return;
  }

  // If token is provided, validate it
  await authenticate(req, res, next);
};