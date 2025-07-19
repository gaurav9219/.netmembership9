# Enterprise RBAC System

A comprehensive Role-Based Access Control (RBAC) system built with Node.js, React, and PostgreSQL, designed to meet enterprise-grade security standards.

## 🚀 Features

### Backend (Node.js/Express)
- **JWT Authentication** with refresh token rotation
- **Role-Based Authorization** with granular permissions
- **PostgreSQL Database** with optimized indexes and relationships
- **Comprehensive Audit Logging** for security compliance
- **Rate Limiting** and DDoS protection
- **Input Validation** with Joi schemas
- **Password Security** with bcrypt and strength validation
- **Session Management** with device tracking
- **CORS Configuration** and security headers
- **OpenAPI 3.0 Compliant** REST API

### Frontend (React)
- **React 18** with TypeScript
- **Protected Routes** based on user roles/permissions
- **Role-based UI Components** with conditional rendering
- **Form Validation** for user management
- **Admin Dashboard** for system management
- **Responsive Design** with modern UI/UX

### Security Features
- **Multi-layer Authentication** (JWT + Refresh tokens)
- **Account Lockout** after failed login attempts
- **Password Complexity** requirements
- **SQL Injection** prevention
- **XSS Protection** with content security policy
- **CSRF Protection** for state-changing operations
- **Secure Headers** with Helmet.js
- **Audit Trail** for all security events

## 📋 Prerequisites

- Node.js 18+ and npm 9+
- PostgreSQL 12+
- Git

## 🛠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd rbac-system
npm install
```

### 2. Database Setup

Create PostgreSQL databases:

```sql
CREATE DATABASE rbac_dev;
CREATE DATABASE rbac_test;
```

### 3. Environment Configuration

Copy the environment files and configure them:

```bash
# Backend configuration
cp backend/.env.example backend/.env

# Frontend configuration (will be created later)
cp frontend/.env.example frontend/.env
```

Edit `backend/.env` with your settings:

```env
# Server Configuration
NODE_ENV=development
PORT=3001

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=rbac_dev
DB_USER=postgres
DB_PASSWORD=your_password

# JWT Configuration (CHANGE IN PRODUCTION)
JWT_ACCESS_SECRET=your-super-secret-access-token-key-min-32-chars
JWT_REFRESH_SECRET=your-super-secret-refresh-token-key-min-32-chars
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Security Configuration
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_TIME=15m

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS Configuration
CORS_ORIGIN=http://localhost:3000
```

### 4. Database Migration & Seeding

```bash
cd backend
npm install
npm run db:migrate
npm run db:seed
```

### 5. Start Development Servers

```bash
# From project root
npm run dev
```

Or start individually:

```bash
# Backend (Terminal 1)
cd backend && npm run dev

# Frontend (Terminal 2)
cd frontend && npm start
```

## 📊 Database Schema

### Core Tables

- **users**: User accounts with security fields
- **roles**: System and custom roles
- **permissions**: Granular permission system
- **user_roles**: User-role assignments with expiration
- **role_permissions**: Role-permission mappings
- **refresh_tokens**: Secure token storage
- **audit_logs**: Comprehensive audit trail

### Key Relationships

```
Users ←→ UserRoles ←→ Roles ←→ RolePermissions ←→ Permissions
Users ←→ RefreshTokens
Users ←→ AuditLogs
```

## 🔐 Default System Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| **super-admin** | Full system access | All permissions |
| **admin** | User & role management | User/role/permission management + audit logs |
| **user-manager** | Limited user management | User CRUD + role assignment |
| **auditor** | Read-only audit access | Audit logs + user/role viewing |
| **user** | Standard user | Profile management + session control |

## 🌐 API Endpoints

### Authentication
```
POST   /api/auth/login           # User login
POST   /api/auth/refresh         # Refresh access token
POST   /api/auth/logout          # Logout single session
POST   /api/auth/logout-all      # Logout all sessions
GET    /api/auth/sessions        # Get user sessions
DELETE /api/auth/sessions/:id    # Revoke specific session
```

### User Management
```
GET    /api/users               # List users (paginated)
POST   /api/users               # Create user
GET    /api/users/:id           # Get user details
PUT    /api/users/:id           # Update user
DELETE /api/users/:id           # Delete user
POST   /api/users/:id/roles     # Assign role to user
DELETE /api/users/:id/roles/:roleId # Revoke role from user
PUT    /api/users/:id/password  # Change user password
```

### Role Management
```
GET    /api/roles               # List roles
POST   /api/roles               # Create role
GET    /api/roles/:id           # Get role details
PUT    /api/roles/:id           # Update role
DELETE /api/roles/:id           # Delete role
POST   /api/roles/:id/permissions # Assign permissions to role
DELETE /api/roles/:id/permissions/:permId # Revoke permission from role
```

### Permission Management
```
GET    /api/permissions         # List permissions
POST   /api/permissions         # Create permission
GET    /api/permissions/:id     # Get permission details
PUT    /api/permissions/:id     # Update permission
DELETE /api/permissions/:id     # Delete permission
```

### Audit Logs
```
GET    /api/audit               # List audit logs (paginated)
GET    /api/audit/:id           # Get audit log details
GET    /api/audit/summary       # Get security summary
GET    /api/audit/user/:id      # Get user activity summary
```

## 🛡️ Security Best Practices

### Password Security
- Minimum 8 characters with complexity requirements
- bcrypt hashing with configurable rounds
- Password history prevention (future enhancement)

### Authentication Security
- JWT access tokens (short-lived: 15 minutes)
- Refresh tokens (7 days) with rotation option
- Account lockout after 5 failed attempts
- Session tracking with device information

### Authorization Security
- Fine-grained permission system
- Resource-based access control
- System role protection
- Ownership-based access for user resources

### API Security
- Rate limiting (100 requests per 15 minutes)
- CORS configuration
- Security headers (Helmet.js)
- Input validation and sanitization
- SQL injection prevention

## 🧪 Testing

```bash
# Backend tests
cd backend && npm test

# Frontend tests
cd frontend && npm test

# Run all tests
npm test
```

## 📦 Production Deployment

### Environment Setup

1. **Set secure JWT secrets** (minimum 32 characters)
2. **Configure production database** with SSL
3. **Set up reverse proxy** (nginx/Apache)
4. **Configure HTTPS** with SSL certificates
5. **Set up monitoring** and logging

### Docker Deployment (Optional)

```bash
# Build and run with Docker Compose
docker-compose up -d
```

### Security Checklist for Production

- [ ] Change all default passwords and secrets
- [ ] Enable database SSL connections
- [ ] Configure firewall rules
- [ ] Set up HTTPS with valid certificates
- [ ] Enable audit log retention policy
- [ ] Configure backup strategy
- [ ] Set up monitoring and alerting
- [ ] Review and test disaster recovery

## 🔧 Configuration Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | development | Environment mode |
| `PORT` | 3001 | Server port |
| `DB_*` | localhost | Database connection settings |
| `JWT_ACCESS_SECRET` | - | JWT access token secret (required) |
| `JWT_REFRESH_SECRET` | - | JWT refresh token secret (required) |
| `BCRYPT_ROUNDS` | 12 | Password hashing rounds |
| `MAX_LOGIN_ATTEMPTS` | 5 | Failed login threshold |
| `LOCKOUT_TIME` | 15m | Account lockout duration |
| `RATE_LIMIT_MAX_REQUESTS` | 100 | Rate limit threshold |

### Security Configuration

```javascript
// Example: Custom rate limiting
const customLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  message: 'Too many requests'
});

app.use('/api/auth/login', customLimiter);
```

## 📚 Architecture Overview

### Backend Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Controllers   │────│    Services     │────│   Database      │
│   (Express)     │    │   (Business)    │    │ (PostgreSQL)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Middleware    │    │   Validation    │    │   Migrations    │
│ (Auth/RBAC)     │    │    (Joi)        │    │   & Seeds       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Frontend Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Components    │────│     Hooks       │────│     Context     │
│    (React)      │    │   (Custom)      │    │   (Auth/App)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Routes      │    │    Services     │    │     Utils       │
│  (Protected)    │    │  (API Client)   │    │  (Validation)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the audit logs for security events

## 🔄 Changelog

### v1.0.0 (Initial Release)
- Complete RBAC implementation
- JWT authentication with refresh tokens
- Comprehensive audit logging
- Admin dashboard
- Security hardening
- API documentation

---

**⚠️ Security Notice**: This system handles authentication and authorization. Always follow security best practices and keep dependencies updated.