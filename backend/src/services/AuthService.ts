import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import db from '../config/database';
import { 
  generateAccessToken, 
  generateRefreshToken, 
  verifyRefreshToken,
  getTokenExpirationTime 
} from '../config/jwt';
import { comparePassword } from '../utils/password';
import { 
  LoginRequest,
  AuthResponse,
  ServiceResult,
  RefreshToken
} from '../types';
import { UserService } from './UserService';
import { AuditService } from './AuditService';

export class AuthService {
  private userService: UserService;
  private auditService: AuditService;

  constructor() {
    this.userService = new UserService();
    this.auditService = new AuditService();
  }

  /**
   * Authenticate user with email and password
   */
  async login(credentials: LoginRequest, ipAddress?: string, userAgent?: string): Promise<ServiceResult<AuthResponse>> {
    const trx = await db.transaction();
    
    try {
      // Find user by email
      const user = await this.userService.findByEmail(credentials.email);
      
      if (!user) {
        await this.userService.handleFailedLogin(credentials.email, ipAddress);
        return {
          success: false,
          error: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS'
        };
      }

      // Check if account is locked
      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        await this.auditService.logSecurityEvent(
          'login_attempt_locked_account',
          user.id,
          ipAddress,
          userAgent,
          { email: credentials.email },
          'failure'
        );
        
        return {
          success: false,
          error: 'Account is temporarily locked',
          code: 'ACCOUNT_LOCKED',
          data: { locked_until: user.locked_until }
        };
      }

      // Check if account is active
      if (!user.is_active) {
        await this.auditService.logSecurityEvent(
          'login_attempt_inactive_account',
          user.id,
          ipAddress,
          userAgent,
          { email: credentials.email },
          'failure'
        );
        
        return {
          success: false,
          error: 'Account is deactivated',
          code: 'ACCOUNT_DEACTIVATED'
        };
      }

      // Verify password
      const isPasswordValid = await comparePassword(credentials.password, user.password_hash);
      
      if (!isPasswordValid) {
        await this.userService.handleFailedLogin(credentials.email, ipAddress);
        return {
          success: false,
          error: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS'
        };
      }

      // Get user roles and permissions
      const userRoles = await this.userService.getUserRoles(user.id);
      const userPermissions = await this.userService.getUserPermissions(user.id);

      // Generate tokens
      const tokenId = uuidv4();
      const accessToken = generateAccessToken({
        sub: user.id,
        email: user.email,
        roles: userRoles.map(role => role.name),
        permissions: userPermissions.map(permission => `${permission.resource}:${permission.action}`)
      });

      const refreshToken = generateRefreshToken({
        sub: user.id,
        token_id: tokenId
      });

      // Store refresh token
      const refreshTokenHash = this.hashToken(refreshToken);
      const refreshTokenExpiry = new Date();
      refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7); // 7 days

      await trx('refresh_tokens').insert({
        id: tokenId,
        user_id: user.id,
        token_hash: refreshTokenHash,
        device_info: userAgent,
        ip_address: ipAddress,
        expires_at: refreshTokenExpiry
      });

      await trx.commit();

      // Handle successful login
      await this.userService.handleSuccessfulLogin(user.id, ipAddress);

      // Create user response
      const userResponse = {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        is_active: user.is_active,
        email_verified: user.email_verified,
        last_login_at: new Date(),
        created_at: user.created_at,
        roles: userRoles.map(role => ({
          id: role.id,
          name: role.name,
          description: role.description,
          is_system_role: role.is_system_role,
          created_at: role.created_at
        })),
        permissions: userPermissions.map(permission => `${permission.resource}:${permission.action}`)
      };

      const authResponse: AuthResponse = {
        access_token: accessToken,
        refresh_token: refreshToken,
        user: userResponse,
        expires_in: getTokenExpirationTime()
      };

      return {
        success: true,
        data: authResponse
      };

    } catch (error) {
      await trx.rollback();
      console.error('Login error:', error);
      
      await this.auditService.logSecurityEvent(
        'login_error',
        undefined,
        ipAddress,
        userAgent,
        { email: credentials.email, error: error instanceof Error ? error.message : 'Unknown error' },
        'failure'
      );

      return {
        success: false,
        error: 'Login failed',
        code: 'LOGIN_ERROR'
      };
    }
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(refreshToken: string, ipAddress?: string, userAgent?: string): Promise<ServiceResult<AuthResponse>> {
    const trx = await db.transaction();
    
    try {
      // Verify refresh token
      const payload = verifyRefreshToken(refreshToken);
      const refreshTokenHash = this.hashToken(refreshToken);

      // Find refresh token in database
      const storedToken = await trx('refresh_tokens')
        .where('id', payload.token_id)
        .where('token_hash', refreshTokenHash)
        .where('is_revoked', false)
        .where('expires_at', '>', new Date())
        .first();

      if (!storedToken) {
        await trx.rollback();
        
        await this.auditService.logSecurityEvent(
          'refresh_token_invalid',
          payload.sub,
          ipAddress,
          userAgent,
          { token_id: payload.token_id },
          'failure'
        );

        return {
          success: false,
          error: 'Invalid or expired refresh token',
          code: 'INVALID_REFRESH_TOKEN'
        };
      }

      // Get user
      const user = await this.userService.findById(payload.sub);
      if (!user || !user.is_active) {
        await trx.rollback();
        return {
          success: false,
          error: 'User not found or inactive',
          code: 'USER_INACTIVE'
        };
      }

      // Update refresh token last used
      await trx('refresh_tokens')
        .where('id', payload.token_id)
        .update({
          last_used_at: new Date(),
          ip_address: ipAddress
        });

      // Get user roles and permissions
      const userRoles = await this.userService.getUserRoles(user.id);
      const userPermissions = await this.userService.getUserPermissions(user.id);

      // Generate new access token
      const newAccessToken = generateAccessToken({
        sub: user.id,
        email: user.email,
        roles: userRoles.map(role => role.name),
        permissions: userPermissions.map(permission => `${permission.resource}:${permission.action}`)
      });

      // Optionally rotate refresh token (recommended for high security)
      let newRefreshToken = refreshToken;
      if (process.env.ROTATE_REFRESH_TOKENS === 'true') {
        // Revoke old token
        await trx('refresh_tokens')
          .where('id', payload.token_id)
          .update({
            is_revoked: true,
            revoked_at: new Date()
          });

        // Create new refresh token
        const newTokenId = uuidv4();
        newRefreshToken = generateRefreshToken({
          sub: user.id,
          token_id: newTokenId
        });

        const newRefreshTokenHash = this.hashToken(newRefreshToken);
        const refreshTokenExpiry = new Date();
        refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);

        await trx('refresh_tokens').insert({
          id: newTokenId,
          user_id: user.id,
          token_hash: newRefreshTokenHash,
          device_info: userAgent,
          ip_address: ipAddress,
          expires_at: refreshTokenExpiry
        });
      }

      await trx.commit();

      // Log successful token refresh
      await this.auditService.log({
        user_id: user.id,
        action: 'token_refreshed',
        resource_type: 'auth',
        ip_address: ipAddress,
        user_agent: userAgent,
        status: 'success'
      });

      // Create user response
      const userResponse = {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        is_active: user.is_active,
        email_verified: user.email_verified,
        last_login_at: user.last_login_at,
        created_at: user.created_at,
        roles: userRoles.map(role => ({
          id: role.id,
          name: role.name,
          description: role.description,
          is_system_role: role.is_system_role,
          created_at: role.created_at
        })),
        permissions: userPermissions.map(permission => `${permission.resource}:${permission.action}`)
      };

      const authResponse: AuthResponse = {
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
        user: userResponse,
        expires_in: getTokenExpirationTime()
      };

      return {
        success: true,
        data: authResponse
      };

    } catch (error) {
      await trx.rollback();
      console.error('Refresh token error:', error);

      await this.auditService.logSecurityEvent(
        'refresh_token_error',
        undefined,
        ipAddress,
        userAgent,
        { error: error instanceof Error ? error.message : 'Unknown error' },
        'failure'
      );

      return {
        success: false,
        error: 'Token refresh failed',
        code: 'REFRESH_TOKEN_ERROR'
      };
    }
  }

  /**
   * Logout user and revoke refresh token
   */
  async logout(refreshToken: string, userId?: string, ipAddress?: string): Promise<ServiceResult<boolean>> {
    try {
      const refreshTokenHash = this.hashToken(refreshToken);

      // Revoke the specific refresh token
      const revokedCount = await db('refresh_tokens')
        .where('token_hash', refreshTokenHash)
        .update({
          is_revoked: true,
          revoked_at: new Date()
        });

      // Log logout event
      if (userId) {
        await this.auditService.log({
          user_id: userId,
          action: 'logout',
          resource_type: 'auth',
          ip_address: ipAddress,
          status: 'success'
        });
      }

      return {
        success: true,
        data: revokedCount > 0
      };

    } catch (error) {
      console.error('Logout error:', error);
      return {
        success: false,
        error: 'Logout failed',
        code: 'LOGOUT_ERROR'
      };
    }
  }

  /**
   * Logout from all devices (revoke all refresh tokens)
   */
  async logoutAllDevices(userId: string, ipAddress?: string): Promise<ServiceResult<boolean>> {
    try {
      // Revoke all user's refresh tokens
      const revokedCount = await db('refresh_tokens')
        .where('user_id', userId)
        .where('is_revoked', false)
        .update({
          is_revoked: true,
          revoked_at: new Date()
        });

      // Log logout all event
      await this.auditService.log({
        user_id: userId,
        action: 'logout_all_devices',
        resource_type: 'auth',
        ip_address: ipAddress,
        status: 'success',
        metadata: { revoked_tokens: revokedCount }
      });

      return {
        success: true,
        data: true
      };

    } catch (error) {
      console.error('Logout all devices error:', error);
      return {
        success: false,
        error: 'Logout from all devices failed',
        code: 'LOGOUT_ALL_ERROR'
      };
    }
  }

  /**
   * Get user's active sessions
   */
  async getUserSessions(userId: string): Promise<ServiceResult<any[]>> {
    try {
      const sessions = await db('refresh_tokens')
        .select('id', 'device_info', 'ip_address', 'created_at', 'last_used_at', 'expires_at')
        .where('user_id', userId)
        .where('is_revoked', false)
        .where('expires_at', '>', new Date())
        .orderBy('last_used_at', 'desc');

      const sessionData = sessions.map(session => ({
        id: session.id,
        device_info: session.device_info,
        ip_address: session.ip_address,
        created_at: session.created_at,
        last_used_at: session.last_used_at,
        expires_at: session.expires_at,
        is_current: false // This would need to be determined by comparing with current token
      }));

      return {
        success: true,
        data: sessionData
      };

    } catch (error) {
      console.error('Get user sessions error:', error);
      return {
        success: false,
        error: 'Failed to get user sessions',
        code: 'GET_SESSIONS_ERROR'
      };
    }
  }

  /**
   * Revoke specific session
   */
  async revokeSession(sessionId: string, userId: string): Promise<ServiceResult<boolean>> {
    try {
      const revokedCount = await db('refresh_tokens')
        .where('id', sessionId)
        .where('user_id', userId)
        .update({
          is_revoked: true,
          revoked_at: new Date()
        });

      if (revokedCount === 0) {
        return {
          success: false,
          error: 'Session not found',
          code: 'SESSION_NOT_FOUND'
        };
      }

      // Log session revocation
      await this.auditService.log({
        user_id: userId,
        action: 'session_revoked',
        resource_type: 'auth',
        resource_id: sessionId,
        status: 'success'
      });

      return {
        success: true,
        data: true
      };

    } catch (error) {
      console.error('Revoke session error:', error);
      return {
        success: false,
        error: 'Failed to revoke session',
        code: 'REVOKE_SESSION_ERROR'
      };
    }
  }

  /**
   * Clean up expired refresh tokens
   */
  async cleanupExpiredTokens(): Promise<ServiceResult<number>> {
    try {
      const deletedCount = await db('refresh_tokens')
        .where('expires_at', '<', new Date())
        .orWhere('is_revoked', true)
        .del();

      console.log(`Cleaned up ${deletedCount} expired/revoked refresh tokens`);

      return {
        success: true,
        data: deletedCount
      };

    } catch (error) {
      console.error('Cleanup expired tokens error:', error);
      return {
        success: false,
        error: 'Failed to cleanup expired tokens',
        code: 'CLEANUP_TOKENS_ERROR'
      };
    }
  }

  /**
   * Hash token for secure storage
   */
  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}