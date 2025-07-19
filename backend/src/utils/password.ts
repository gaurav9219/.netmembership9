import bcrypt from 'bcryptjs';

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12');

/**
 * Hash a password using bcrypt
 */
export const hashPassword = async (password: string): Promise<string> => {
  try {
    return await bcrypt.hash(password, BCRYPT_ROUNDS);
  } catch (error) {
    throw new Error('Failed to hash password');
  }
};

/**
 * Compare a password with its hash
 */
export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    throw new Error('Failed to compare password');
  }
};

/**
 * Validate password strength
 */
export const validatePasswordStrength = (password: string): { isValid: boolean; errors: string[] } => {
  const errors: string[] = [];

  // Minimum length
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }

  // Maximum length (to prevent DoS attacks)
  if (password.length > 128) {
    errors.push('Password must be no more than 128 characters long');
  }

  // Must contain lowercase letter
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  // Must contain uppercase letter
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  // Must contain number
  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  // Must contain special character
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  // Common password patterns to avoid
  const commonPatterns = [
    /(.)\1{3,}/, // Same character repeated 4+ times
    /123456|654321/, // Sequential numbers
    /abcdef|fedcba/, // Sequential letters
    /password|123456|qwerty|admin/i // Common passwords
  ];

  for (const pattern of commonPatterns) {
    if (pattern.test(password)) {
      errors.push('Password contains common patterns that are not allowed');
      break;
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Generate a random password
 */
export const generateRandomPassword = (length: number = 12): string => {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*(),.?":{}|<>';
  
  const allChars = lowercase + uppercase + numbers + symbols;
  
  let password = '';
  
  // Ensure at least one character from each category
  password += lowercase[Math.floor(Math.random() * lowercase.length)];
  password += uppercase[Math.floor(Math.random() * uppercase.length)];
  password += numbers[Math.floor(Math.random() * numbers.length)];
  password += symbols[Math.floor(Math.random() * symbols.length)];
  
  // Fill the rest with random characters
  for (let i = 4; i < length; i++) {
    password += allChars[Math.floor(Math.random() * allChars.length)];
  }
  
  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
};