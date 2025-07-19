import Joi from 'joi';
import { validatePasswordStrength } from './password';

// Custom password validator
const passwordValidator = (value: string, helpers: any) => {
  const validation = validatePasswordStrength(value);
  if (!validation.isValid) {
    return helpers.error('password.strength', { errors: validation.errors });
  }
  return value;
};

// Custom Joi extension for password validation
const customJoi = Joi.extend({
  type: 'password',
  base: Joi.string(),
  messages: {
    'password.strength': 'Password does not meet strength requirements: {{#errors}}'
  },
  rules: {
    strength: {
      method() {
        return this.$_addRule('strength');
      },
      validate: passwordValidator
    }
  }
});

// User validation schemas
export const createUserSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .max(255)
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'string.max': 'Email must be less than 255 characters',
      'any.required': 'Email is required'
    }),
  
  password: (customJoi as any).password()
    .strength()
    .required()
    .messages({
      'any.required': 'Password is required'
    }),
  
  first_name: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z\s'-]+$/)
    .required()
    .messages({
      'string.min': 'First name must not be empty',
      'string.max': 'First name must be less than 100 characters',
      'string.pattern.base': 'First name can only contain letters, spaces, hyphens, and apostrophes',
      'any.required': 'First name is required'
    }),
  
  last_name: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z\s'-]+$/)
    .required()
    .messages({
      'string.min': 'Last name must not be empty',
      'string.max': 'Last name must be less than 100 characters',
      'string.pattern.base': 'Last name can only contain letters, spaces, hyphens, and apostrophes',
      'any.required': 'Last name is required'
    })
});

export const updateUserSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .max(255)
    .messages({
      'string.email': 'Please provide a valid email address',
      'string.max': 'Email must be less than 255 characters'
    }),
  
  first_name: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z\s'-]+$/)
    .messages({
      'string.min': 'First name must not be empty',
      'string.max': 'First name must be less than 100 characters',
      'string.pattern.base': 'First name can only contain letters, spaces, hyphens, and apostrophes'
    }),
  
  last_name: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z\s'-]+$/)
    .messages({
      'string.min': 'Last name must not be empty',
      'string.max': 'Last name must be less than 100 characters',
      'string.pattern.base': 'Last name can only contain letters, spaces, hyphens, and apostrophes'
    }),
  
  is_active: Joi.boolean()
    .messages({
      'boolean.base': 'is_active must be a boolean value'
    })
});

export const loginSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
  
  password: Joi.string()
    .min(1)
    .required()
    .messages({
      'string.min': 'Password is required',
      'any.required': 'Password is required'
    })
});

export const changePasswordSchema = Joi.object({
  current_password: Joi.string()
    .min(1)
    .required()
    .messages({
      'string.min': 'Current password is required',
      'any.required': 'Current password is required'
    }),
  
  new_password: (customJoi as any).password()
    .strength()
    .required()
    .messages({
      'any.required': 'New password is required'
    })
});

// Role validation schemas
export const createRoleSchema = Joi.object({
  name: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z0-9_\s-]+$/)
    .required()
    .messages({
      'string.min': 'Role name must not be empty',
      'string.max': 'Role name must be less than 100 characters',
      'string.pattern.base': 'Role name can only contain letters, numbers, underscores, spaces, and hyphens',
      'any.required': 'Role name is required'
    }),
  
  description: Joi.string()
    .max(500)
    .allow('')
    .messages({
      'string.max': 'Description must be less than 500 characters'
    }),
  
  permission_ids: Joi.array()
    .items(Joi.string().uuid())
    .messages({
      'array.base': 'Permission IDs must be an array',
      'string.guid': 'Each permission ID must be a valid UUID'
    })
});

export const updateRoleSchema = Joi.object({
  name: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z0-9_\s-]+$/)
    .messages({
      'string.min': 'Role name must not be empty',
      'string.max': 'Role name must be less than 100 characters',
      'string.pattern.base': 'Role name can only contain letters, numbers, underscores, spaces, and hyphens'
    }),
  
  description: Joi.string()
    .max(500)
    .allow('')
    .messages({
      'string.max': 'Description must be less than 500 characters'
    })
});

// Permission validation schemas
export const createPermissionSchema = Joi.object({
  name: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z0-9_\s-]+$/)
    .required()
    .messages({
      'string.min': 'Permission name must not be empty',
      'string.max': 'Permission name must be less than 100 characters',
      'string.pattern.base': 'Permission name can only contain letters, numbers, underscores, spaces, and hyphens',
      'any.required': 'Permission name is required'
    }),
  
  resource: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z0-9_-]+$/)
    .required()
    .messages({
      'string.min': 'Resource must not be empty',
      'string.max': 'Resource must be less than 100 characters',
      'string.pattern.base': 'Resource can only contain letters, numbers, underscores, and hyphens',
      'any.required': 'Resource is required'
    }),
  
  action: Joi.string()
    .valid('create', 'read', 'update', 'delete', 'assign', 'revoke')
    .required()
    .messages({
      'any.only': 'Action must be one of: create, read, update, delete, assign, revoke',
      'any.required': 'Action is required'
    }),
  
  description: Joi.string()
    .max(500)
    .allow('')
    .messages({
      'string.max': 'Description must be less than 500 characters'
    })
});

export const updatePermissionSchema = Joi.object({
  name: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z0-9_\s-]+$/)
    .messages({
      'string.min': 'Permission name must not be empty',
      'string.max': 'Permission name must be less than 100 characters',
      'string.pattern.base': 'Permission name can only contain letters, numbers, underscores, spaces, and hyphens'
    }),
  
  resource: Joi.string()
    .min(1)
    .max(100)
    .pattern(/^[a-zA-Z0-9_-]+$/)
    .messages({
      'string.min': 'Resource must not be empty',
      'string.max': 'Resource must be less than 100 characters',
      'string.pattern.base': 'Resource can only contain letters, numbers, underscores, and hyphens'
    }),
  
  action: Joi.string()
    .valid('create', 'read', 'update', 'delete', 'assign', 'revoke')
    .messages({
      'any.only': 'Action must be one of: create, read, update, delete, assign, revoke'
    }),
  
  description: Joi.string()
    .max(500)
    .allow('')
    .messages({
      'string.max': 'Description must be less than 500 characters'
    })
});

// Role assignment validation
export const assignRoleSchema = Joi.object({
  user_id: Joi.string()
    .uuid()
    .required()
    .messages({
      'string.guid': 'User ID must be a valid UUID',
      'any.required': 'User ID is required'
    }),
  
  role_id: Joi.string()
    .uuid()
    .required()
    .messages({
      'string.guid': 'Role ID must be a valid UUID',
      'any.required': 'Role ID is required'
    }),
  
  expires_at: Joi.date()
    .iso()
    .min('now')
    .messages({
      'date.base': 'Expiration date must be a valid date',
      'date.format': 'Expiration date must be in ISO format',
      'date.min': 'Expiration date must be in the future'
    })
});

// Permission assignment validation
export const assignPermissionSchema = Joi.object({
  role_id: Joi.string()
    .uuid()
    .required()
    .messages({
      'string.guid': 'Role ID must be a valid UUID',
      'any.required': 'Role ID is required'
    }),
  
  permission_ids: Joi.array()
    .items(Joi.string().uuid())
    .min(1)
    .required()
    .messages({
      'array.base': 'Permission IDs must be an array',
      'array.min': 'At least one permission ID is required',
      'string.guid': 'Each permission ID must be a valid UUID',
      'any.required': 'Permission IDs are required'
    })
});

// Query parameter validation
export const paginationSchema = Joi.object({
  page: Joi.number()
    .integer()
    .min(1)
    .default(1)
    .messages({
      'number.base': 'Page must be a number',
      'number.integer': 'Page must be an integer',
      'number.min': 'Page must be at least 1'
    }),
  
  limit: Joi.number()
    .integer()
    .min(1)
    .max(100)
    .default(10)
    .messages({
      'number.base': 'Limit must be a number',
      'number.integer': 'Limit must be an integer',
      'number.min': 'Limit must be at least 1',
      'number.max': 'Limit must be at most 100'
    }),
  
  sort: Joi.string()
    .max(50)
    .messages({
      'string.max': 'Sort field must be less than 50 characters'
    }),
  
  order: Joi.string()
    .valid('asc', 'desc')
    .default('asc')
    .messages({
      'any.only': 'Order must be either "asc" or "desc"'
    })
});

export const userQuerySchema = paginationSchema.keys({
  search: Joi.string()
    .max(100)
    .messages({
      'string.max': 'Search term must be less than 100 characters'
    }),
  
  is_active: Joi.boolean()
    .messages({
      'boolean.base': 'is_active must be a boolean value'
    }),
  
  role: Joi.string()
    .uuid()
    .messages({
      'string.guid': 'Role ID must be a valid UUID'
    })
});

export const roleQuerySchema = paginationSchema.keys({
  search: Joi.string()
    .max(100)
    .messages({
      'string.max': 'Search term must be less than 100 characters'
    }),
  
  is_system_role: Joi.boolean()
    .messages({
      'boolean.base': 'is_system_role must be a boolean value'
    })
});

export const permissionQuerySchema = paginationSchema.keys({
  search: Joi.string()
    .max(100)
    .messages({
      'string.max': 'Search term must be less than 100 characters'
    }),
  
  resource: Joi.string()
    .max(100)
    .messages({
      'string.max': 'Resource must be less than 100 characters'
    }),
  
  action: Joi.string()
    .valid('create', 'read', 'update', 'delete', 'assign', 'revoke')
    .messages({
      'any.only': 'Action must be one of: create, read, update, delete, assign, revoke'
    })
});

export const auditLogQuerySchema = paginationSchema.keys({
  user_id: Joi.string()
    .uuid()
    .messages({
      'string.guid': 'User ID must be a valid UUID'
    }),
  
  action: Joi.string()
    .max(100)
    .messages({
      'string.max': 'Action must be less than 100 characters'
    }),
  
  resource_type: Joi.string()
    .max(50)
    .messages({
      'string.max': 'Resource type must be less than 50 characters'
    }),
  
  status: Joi.string()
    .valid('success', 'failure', 'warning')
    .messages({
      'any.only': 'Status must be one of: success, failure, warning'
    }),
  
  start_date: Joi.date()
    .iso()
    .messages({
      'date.base': 'Start date must be a valid date',
      'date.format': 'Start date must be in ISO format'
    }),
  
  end_date: Joi.date()
    .iso()
    .min(Joi.ref('start_date'))
    .messages({
      'date.base': 'End date must be a valid date',
      'date.format': 'End date must be in ISO format',
      'date.min': 'End date must be after start date'
    })
});

// UUID parameter validation
export const uuidSchema = Joi.string()
  .uuid()
  .required()
  .messages({
    'string.guid': 'ID must be a valid UUID',
    'any.required': 'ID is required'
  });