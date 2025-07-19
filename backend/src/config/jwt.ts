import jwt from 'jsonwebtoken';
import { AccessTokenPayload, RefreshTokenPayload, JWTConfig } from '../types';

const jwtConfig: JWTConfig = {
  access_secret: process.env.JWT_ACCESS_SECRET || 'fallback-secret-change-in-production',
  refresh_secret: process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret-change-in-production',
  access_expires_in: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
  refresh_expires_in: process.env.JWT_REFRESH_EXPIRES_IN || '7d'
};

// Validate JWT configuration on startup
if (process.env.NODE_ENV === 'production') {
  if (jwtConfig.access_secret.includes('fallback') || jwtConfig.refresh_secret.includes('fallback')) {
    throw new Error('JWT secrets must be set in production environment');
  }
  
  if (jwtConfig.access_secret.length < 32 || jwtConfig.refresh_secret.length < 32) {
    throw new Error('JWT secrets must be at least 32 characters long in production');
  }
}

/**
 * Generate access token with user permissions
 */
export const generateAccessToken = (payload: Omit<AccessTokenPayload, 'iat' | 'exp'>): string => {
  return jwt.sign(payload, jwtConfig.access_secret, {
    expiresIn: jwtConfig.access_expires_in,
    issuer: 'rbac-system',
    audience: 'rbac-users'
  });
};

/**
 * Generate refresh token
 */
export const generateRefreshToken = (payload: Omit<RefreshTokenPayload, 'iat' | 'exp'>): string => {
  return jwt.sign(payload, jwtConfig.refresh_secret, {
    expiresIn: jwtConfig.refresh_expires_in,
    issuer: 'rbac-system',
    audience: 'rbac-users'
  });
};

/**
 * Verify access token
 */
export const verifyAccessToken = (token: string): AccessTokenPayload => {
  try {
    return jwt.verify(token, jwtConfig.access_secret, {
      issuer: 'rbac-system',
      audience: 'rbac-users'
    }) as AccessTokenPayload;
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid access token');
    }
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Access token expired');
    }
    throw new Error('Token verification failed');
  }
};

/**
 * Verify refresh token
 */
export const verifyRefreshToken = (token: string): RefreshTokenPayload => {
  try {
    return jwt.verify(token, jwtConfig.refresh_secret, {
      issuer: 'rbac-system',
      audience: 'rbac-users'
    }) as RefreshTokenPayload;
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid refresh token');
    }
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Refresh token expired');
    }
    throw new Error('Token verification failed');
  }
};

/**
 * Decode token without verification (for debugging)
 */
export const decodeToken = (token: string): any => {
  return jwt.decode(token);
};

/**
 * Get token expiration time in seconds
 */
export const getTokenExpirationTime = (): number => {
  // Convert access token expiration to seconds
  const expiresIn = jwtConfig.access_expires_in;
  
  if (expiresIn.endsWith('m')) {
    return parseInt(expiresIn) * 60;
  }
  if (expiresIn.endsWith('h')) {
    return parseInt(expiresIn) * 3600;
  }
  if (expiresIn.endsWith('d')) {
    return parseInt(expiresIn) * 86400;
  }
  
  // Default to 15 minutes if format is not recognized
  return 900;
};

export { jwtConfig };