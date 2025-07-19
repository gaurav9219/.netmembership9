import db from '../config/database';
import { 
  AuditLog, 
  AuditLogQuery, 
  PaginatedResponse,
  ServiceResult 
} from '../types';

interface AuditLogInput {
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
}

export class AuditService {
  /**
   * Log an audit event
   */
  async log(logData: AuditLogInput): Promise<void> {
    try {
      await db('audit_logs').insert({
        user_id: logData.user_id,
        action: logData.action,
        resource_type: logData.resource_type,
        resource_id: logData.resource_id,
        old_values: logData.old_values ? JSON.stringify(logData.old_values) : null,
        new_values: logData.new_values ? JSON.stringify(logData.new_values) : null,
        ip_address: logData.ip_address,
        user_agent: logData.user_agent,
        status: logData.status,
        failure_reason: logData.failure_reason,
        metadata: logData.metadata ? JSON.stringify(logData.metadata) : null,
        created_at: new Date()
      });
    } catch (error) {
      console.error('Error logging audit event:', error);
      // Don't throw error to avoid breaking the main operation
    }
  }

  /**
   * Get audit logs with filtering and pagination
   */
  async getAuditLogs(query: AuditLogQuery): Promise<PaginatedResponse<AuditLog>> {
    try {
      const { 
        page = 1, 
        limit = 10, 
        user_id, 
        action, 
        resource_type, 
        status, 
        start_date, 
        end_date,
        sort = 'created_at',
        order = 'desc'
      } = query;
      
      const offset = (page - 1) * limit;

      let baseQuery = db('audit_logs')
        .select('audit_logs.*', 'users.email as user_email')
        .leftJoin('users', 'audit_logs.user_id', 'users.id');

      // Apply filters
      if (user_id) {
        baseQuery = baseQuery.where('audit_logs.user_id', user_id);
      }

      if (action) {
        baseQuery = baseQuery.where('audit_logs.action', 'ilike', `%${action}%`);
      }

      if (resource_type) {
        baseQuery = baseQuery.where('audit_logs.resource_type', resource_type);
      }

      if (status) {
        baseQuery = baseQuery.where('audit_logs.status', status);
      }

      if (start_date) {
        baseQuery = baseQuery.where('audit_logs.created_at', '>=', start_date);
      }

      if (end_date) {
        baseQuery = baseQuery.where('audit_logs.created_at', '<=', end_date);
      }

      // Get total count
      const countResult = await baseQuery.clone().count('audit_logs.id as count').first();
      const total = parseInt(countResult?.count as string) || 0;

      // Get audit logs with pagination
      const auditLogs = await baseQuery
        .orderBy(`audit_logs.${sort}`, order)
        .limit(limit)
        .offset(offset);

      // Parse JSON fields
      const parsedLogs = auditLogs.map(log => ({
        ...log,
        old_values: log.old_values ? JSON.parse(log.old_values) : null,
        new_values: log.new_values ? JSON.parse(log.new_values) : null,
        metadata: log.metadata ? JSON.parse(log.metadata) : null
      }));

      return {
        data: parsedLogs,
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
      console.error('Error getting audit logs:', error);
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
   * Get audit log by ID
   */
  async getAuditLogById(id: string): Promise<ServiceResult<AuditLog>> {
    try {
      const auditLog = await db('audit_logs')
        .select('audit_logs.*', 'users.email as user_email')
        .leftJoin('users', 'audit_logs.user_id', 'users.id')
        .where('audit_logs.id', id)
        .first();

      if (!auditLog) {
        return {
          success: false,
          error: 'Audit log not found',
          code: 'AUDIT_LOG_NOT_FOUND'
        };
      }

      // Parse JSON fields
      const parsedLog = {
        ...auditLog,
        old_values: auditLog.old_values ? JSON.parse(auditLog.old_values) : null,
        new_values: auditLog.new_values ? JSON.parse(auditLog.new_values) : null,
        metadata: auditLog.metadata ? JSON.parse(auditLog.metadata) : null
      };

      return {
        success: true,
        data: parsedLog
      };

    } catch (error) {
      console.error('Error getting audit log by ID:', error);
      return {
        success: false,
        error: 'Failed to get audit log',
        code: 'GET_AUDIT_LOG_ERROR'
      };
    }
  }

  /**
   * Get user activity summary
   */
  async getUserActivitySummary(userId: string, days: number = 30): Promise<ServiceResult<any>> {
    try {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      const activities = await db('audit_logs')
        .select('action', 'status')
        .count('* as count')
        .where('user_id', userId)
        .where('created_at', '>=', startDate)
        .groupBy('action', 'status')
        .orderBy('count', 'desc');

      const summary = {
        total_activities: activities.reduce((sum, activity) => sum + parseInt(activity.count as string), 0),
        successful_actions: activities
          .filter(activity => activity.status === 'success')
          .reduce((sum, activity) => sum + parseInt(activity.count as string), 0),
        failed_actions: activities
          .filter(activity => activity.status === 'failure')
          .reduce((sum, activity) => sum + parseInt(activity.count as string), 0),
        activities_by_type: activities.map(activity => ({
          action: activity.action,
          status: activity.status,
          count: parseInt(activity.count as string)
        }))
      };

      return {
        success: true,
        data: summary
      };

    } catch (error) {
      console.error('Error getting user activity summary:', error);
      return {
        success: false,
        error: 'Failed to get user activity summary',
        code: 'GET_ACTIVITY_SUMMARY_ERROR'
      };
    }
  }

  /**
   * Get security events summary
   */
  async getSecurityEventsSummary(days: number = 7): Promise<ServiceResult<any>> {
    try {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      // Get failed login attempts
      const failedLogins = await db('audit_logs')
        .count('* as count')
        .where('action', 'login_failed')
        .where('created_at', '>=', startDate)
        .first();

      // Get successful logins
      const successfulLogins = await db('audit_logs')
        .count('* as count')
        .where('action', 'login')
        .where('status', 'success')
        .where('created_at', '>=', startDate)
        .first();

      // Get password changes
      const passwordChanges = await db('audit_logs')
        .count('* as count')
        .where('action', 'password_changed')
        .where('created_at', '>=', startDate)
        .first();

      // Get role assignments
      const roleAssignments = await db('audit_logs')
        .count('* as count')
        .where('action', 'role_assigned')
        .where('created_at', '>=', startDate)
        .first();

      // Get failed actions by IP
      const suspiciousIPs = await db('audit_logs')
        .select('ip_address')
        .count('* as failed_attempts')
        .where('status', 'failure')
        .where('created_at', '>=', startDate)
        .whereNotNull('ip_address')
        .groupBy('ip_address')
        .having('failed_attempts', '>', 5)
        .orderBy('failed_attempts', 'desc')
        .limit(10);

      const summary = {
        period_days: days,
        failed_login_attempts: parseInt(failedLogins?.count as string) || 0,
        successful_logins: parseInt(successfulLogins?.count as string) || 0,
        password_changes: parseInt(passwordChanges?.count as string) || 0,
        role_assignments: parseInt(roleAssignments?.count as string) || 0,
        suspicious_ips: suspiciousIPs.map(ip => ({
          ip_address: ip.ip_address,
          failed_attempts: parseInt(ip.failed_attempts as string)
        }))
      };

      return {
        success: true,
        data: summary
      };

    } catch (error) {
      console.error('Error getting security events summary:', error);
      return {
        success: false,
        error: 'Failed to get security events summary',
        code: 'GET_SECURITY_SUMMARY_ERROR'
      };
    }
  }

  /**
   * Clean up old audit logs (for data retention)
   */
  async cleanupOldLogs(retentionDays: number = 365): Promise<ServiceResult<number>> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const deletedCount = await db('audit_logs')
        .where('created_at', '<', cutoffDate)
        .del();

      console.log(`Cleaned up ${deletedCount} audit logs older than ${retentionDays} days`);

      return {
        success: true,
        data: deletedCount
      };

    } catch (error) {
      console.error('Error cleaning up old audit logs:', error);
      return {
        success: false,
        error: 'Failed to cleanup old audit logs',
        code: 'CLEANUP_LOGS_ERROR'
      };
    }
  }

  /**
   * Log user action with request context
   */
  async logUserAction(
    userId: string, 
    action: string, 
    resourceType: string, 
    resourceId?: string,
    oldValues?: Record<string, any>,
    newValues?: Record<string, any>,
    ipAddress?: string,
    userAgent?: string,
    status: 'success' | 'failure' | 'warning' = 'success',
    failureReason?: string
  ): Promise<void> {
    await this.log({
      user_id: userId,
      action,
      resource_type: resourceType,
      resource_id: resourceId,
      old_values: oldValues,
      new_values: newValues,
      ip_address: ipAddress,
      user_agent: userAgent,
      status,
      failure_reason: failureReason
    });
  }

  /**
   * Log security event
   */
  async logSecurityEvent(
    action: string,
    userId?: string,
    ipAddress?: string,
    userAgent?: string,
    details?: Record<string, any>,
    status: 'success' | 'failure' | 'warning' = 'warning'
  ): Promise<void> {
    await this.log({
      user_id: userId,
      action,
      resource_type: 'security',
      ip_address: ipAddress,
      user_agent: userAgent,
      status,
      metadata: details
    });
  }
}