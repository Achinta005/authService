import { getMongoDb } from "../config/mongodb";
import { LoginLog } from "../models/loginLogs";
import { AuditLog } from "../models/AuditLog";
import { ActivityLog } from "../models/ActivityLog";
import { SecurityEvent } from "../models/SecurityEvent";

export class LogService {
  private get db() {
    return getMongoDb();
  }

  // ============ LOGIN LOGS ============

  async createLoginLog(log: LoginLog) {
    const collection = this.db.collection<LoginLog>("login_logs");
    const result = await collection.insertOne({
      ...log,
      createdAt: new Date(),
    });
    return result;
  }

  // Get user login history with pagination
  async getUserLoginHistory(
    userId: string,
    page: number = 1,
    limit: number = 20,
  ) {
    const collection = this.db.collection<LoginLog>("login_logs");

    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      collection
        .find({ userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      collection.countDocuments({ userId }),
    ]);

    return {
      logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }

  // Get failed login attempts with aggregation
  async getFailedLoginAttempts(timeWindow: number = 3600000) {
    const collection = this.db.collection<LoginLog>("login_logs");

    const startTime = new Date(Date.now() - timeWindow);

    const results = await collection
      .aggregate([
        {
          $match: {
            success: false,
            createdAt: { $gte: startTime },
          },
        },
        {
          $group: {
            _id: "$email",
            attempts: { $sum: 1 },
            lastAttempt: { $max: "$createdAt" },
            ipAddresses: { $addToSet: "$ipAddress" },
          },
        },
        {
          $match: {
            attempts: { $gte: 3 },
          },
        },
        {
          $sort: { attempts: -1 },
        },
      ])
      .toArray();

    return results;
  }

  // Login analytics by method
  async getLoginAnalyticsByMethod(startDate: Date, endDate: Date) {
    const collection = this.db.collection<LoginLog>("login_logs");

    const results = await collection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: startDate, $lte: endDate },
          },
        },
        {
          $group: {
            _id: {
              method: "$loginMethod",
              success: "$success",
            },
            count: { $sum: 1 },
          },
        },
        {
          $group: {
            _id: "$_id.method",
            total: { $sum: "$count" },
            successful: {
              $sum: {
                $cond: [{ $eq: ["$_id.success", true] }, "$count", 0],
              },
            },
            failed: {
              $sum: {
                $cond: [{ $eq: ["$_id.success", false] }, "$count", 0],
              },
            },
          },
        },
        {
          $project: {
            method: "$_id",
            total: 1,
            successful: 1,
            failed: 1,
            successRate: {
              $multiply: [{ $divide: ["$successful", "$total"] }, 100],
            },
          },
        },
      ])
      .toArray();

    return results;
  }

  // Geographic login distribution
  async getLoginsByGeography(startDate: Date, endDate: Date) {
    const collection = this.db.collection<LoginLog>("login_logs");

    const results = await collection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: startDate, $lte: endDate },
            "location.country": { $exists: true },
          },
        },
        {
          $group: {
            _id: {
              country: "$location.country",
              city: "$location.city",
            },
            count: { $sum: 1 },
            uniqueUsers: { $addToSet: "$userId" },
          },
        },
        {
          $project: {
            country: "$_id.country",
            city: "$_id.city",
            loginCount: "$count",
            uniqueUserCount: { $size: "$uniqueUsers" },
          },
        },
        {
          $sort: { loginCount: -1 },
        },
      ])
      .toArray();

    return results;
  }

  // ============ AUDIT LOGS ============

  async createAuditLog(log: AuditLog) {
    const collection = this.db.collection<AuditLog>("audit_logs");
    const result = await collection.insertOne({
      ...log,
      timestamp: new Date(),
    });
    return result;
  }

  // Get audit trail for a specific user
  async getUserAuditTrail(
    userId: string,
    page: number = 1,
    limit: number = 50,
  ) {
    const collection = this.db.collection<AuditLog>("audit_logs");

    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      collection
        .find({ userId })
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      collection.countDocuments({ userId }),
    ]);

    return {
      logs,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    };
  }

  // Get audit logs by action type with time-based grouping
  async getAuditLogsByAction(
    startDate: Date,
    endDate: Date,
    groupBy: "hour" | "day" | "month" = "day",
  ) {
    const collection = this.db.collection<AuditLog>("audit_logs");

    const dateFormat: Record<string, any> = {
      hour: { $dateToString: { format: "%Y-%m-%d %H:00", date: "$timestamp" } },
      day: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
      month: { $dateToString: { format: "%Y-%m", date: "$timestamp" } },
    };

    const results = await collection
      .aggregate([
        {
          $match: {
            timestamp: { $gte: startDate, $lte: endDate },
          },
        },
        {
          $group: {
            _id: {
              period: dateFormat[groupBy],
              action: "$action",
            },
            count: { $sum: 1 },
            uniqueUsers: { $addToSet: "$userId" },
          },
        },
        {
          $group: {
            _id: "$_id.period",
            actions: {
              $push: {
                action: "$_id.action",
                count: "$count",
                uniqueUsers: { $size: "$uniqueUsers" },
              },
            },
            totalEvents: { $sum: "$count" },
          },
        },
        {
          $sort: { _id: 1 },
        },
      ])
      .toArray();

    return results;
  }

  // Track changes to specific resources
  async getResourceChangeHistory(resource: string, resourceId: string) {
    const collection = this.db.collection<AuditLog>("audit_logs");

    const changes = await collection
      .find({
        resource,
        resourceId,
      })
      .sort({ timestamp: -1 })
      .toArray();

    return changes;
  }

  // ============ ACTIVITY LOGS ============

  async createActivityLog(log: ActivityLog) {
    const collection = this.db.collection<ActivityLog>("activity_logs");
    const result = await collection.insertOne({
      ...log,
      timestamp: new Date(),
    });
    return result;
  }

  // User activity summary with multiple metrics
  async getUserActivitySummary(userId: string, startDate: Date, endDate: Date) {
    const collection = this.db.collection<ActivityLog>("activity_logs");

    const results = await collection
      .aggregate([
        {
          $match: {
            userId,
            timestamp: { $gte: startDate, $lte: endDate },
          },
        },
        {
          $facet: {
            eventsByCategory: [
              {
                $group: {
                  _id: "$eventCategory",
                  count: { $sum: 1 },
                },
              },
            ],
            eventsByType: [
              {
                $group: {
                  _id: "$eventType",
                  count: { $sum: 1 },
                },
              },
              {
                $sort: { count: -1 },
              },
              {
                $limit: 10,
              },
            ],
            totalEvents: [
              {
                $count: "count",
              },
            ],
            avgSessionDuration: [
              {
                $match: {
                  duration: { $exists: true },
                },
              },
              {
                $group: {
                  _id: null,
                  avgDuration: { $avg: "$duration" },
                },
              },
            ],
            mostVisitedPages: [
              {
                $match: {
                  page: { $exists: true },
                },
              },
              {
                $group: {
                  _id: "$page",
                  visits: { $sum: 1 },
                },
              },
              {
                $sort: { visits: -1 },
              },
              {
                $limit: 5,
              },
            ],
          },
        },
      ])
      .toArray();

    return results[0];
  }

  // Active users over time
  async getActiveUsers(
    startDate: Date,
    endDate: Date,
    interval: "daily" | "weekly" | "monthly" = "daily",
  ) {
    const collection = this.db.collection<ActivityLog>("activity_logs");

    const groupByFormat: Record<string, any> = {
      daily: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
      weekly: { $isoWeek: "$timestamp" },
      monthly: { $dateToString: { format: "%Y-%m", date: "$timestamp" } },
    };

    const results = await collection
      .aggregate([
        {
          $match: {
            timestamp: { $gte: startDate, $lte: endDate },
          },
        },
        {
          $group: {
            _id: {
              period: groupByFormat[interval],
              userId: "$userId",
            },
          },
        },
        {
          $group: {
            _id: "$_id.period",
            activeUsers: { $sum: 1 },
          },
        },
        {
          $sort: { _id: 1 },
        },
      ])
      .toArray();

    return results;
  }

  // ============ SECURITY EVENTS ============

  async createSecurityEvent(event: SecurityEvent) {
    const collection = this.db.collection<SecurityEvent>("security_events");
    const result = await collection.insertOne({
      ...event,
      timestamp: new Date(),
    });
    return result;
  }

  // Get unresolved security events by severity
  async getUnresolvedSecurityEvents() {
    const collection = this.db.collection<SecurityEvent>("security_events");

    const results = await collection
      .aggregate([
        {
          $match: {
            resolved: false,
          },
        },
        {
          $group: {
            _id: "$severity",
            count: { $sum: 1 },
            events: {
              $push: {
                eventType: "$eventType",
                userId: "$userId",
                timestamp: "$timestamp",
                description: "$description",
              },
            },
          },
        },
        {
          $sort: {
            _id: 1, // Sort by severity: critical, high, medium, low
          },
        },
      ])
      .toArray();

    return results;
  }

  // Security event trends
  async getSecurityEventTrends(days: number = 30) {
    const collection = this.db.collection<SecurityEvent>("security_events");

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const results = await collection
      .aggregate([
        {
          $match: {
            timestamp: { $gte: startDate },
          },
        },
        {
          $group: {
            _id: {
              date: {
                $dateToString: { format: "%Y-%m-%d", date: "$timestamp" },
              },
              eventType: "$eventType",
              severity: "$severity",
            },
            count: { $sum: 1 },
          },
        },
        {
          $group: {
            _id: "$_id.date",
            events: {
              $push: {
                type: "$_id.eventType",
                severity: "$_id.severity",
                count: "$count",
              },
            },
            totalEvents: { $sum: "$count" },
          },
        },
        {
          $sort: { _id: 1 },
        },
      ])
      .toArray();

    return results;
  }

  // Suspicious IP addresses (multiple failed attempts from same IP)
  async getSuspiciousIPs(threshold: number = 5, timeWindow: number = 3600000) {
    const collection = this.db.collection<SecurityEvent>("security_events");

    const startTime = new Date(Date.now() - timeWindow);

    const results = await collection
      .aggregate([
        {
          $match: {
            timestamp: { $gte: startTime },
            eventType: {
              $in: ["suspicious_login", "brute_force_attempt", "mfa_failed"],
            },
          },
        },
        {
          $group: {
            _id: "$ipAddress",
            eventCount: { $sum: 1 },
            eventTypes: { $addToSet: "$eventType" },
            affectedUsers: { $addToSet: "$userId" },
            firstSeen: { $min: "$timestamp" },
            lastSeen: { $max: "$timestamp" },
          },
        },
        {
          $match: {
            eventCount: { $gte: threshold },
          },
        },
        {
          $project: {
            ipAddress: "$_id",
            eventCount: 1,
            eventTypes: 1,
            affectedUserCount: { $size: "$affectedUsers" },
            firstSeen: 1,
            lastSeen: 1,
          },
        },
        {
          $sort: { eventCount: -1 },
        },
      ])
      .toArray();

    return results;
  }

  // ============ CROSS-COLLECTION ANALYTICS ============

  // User engagement score (combines activity and login data)
  async calculateUserEngagementScore(userId: string, days: number = 30) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const loginCollection = this.db.collection<LoginLog>("login_logs");
    const activityCollection = this.db.collection<ActivityLog>("activity_logs");

    const [loginMetrics, activityMetrics] = await Promise.all([
      loginCollection
        .aggregate([
          {
            $match: {
              userId,
              success: true,
              createdAt: { $gte: startDate },
            },
          },
          {
            $group: {
              _id: null,
              loginCount: { $sum: 1 },
              uniqueDays: {
                $addToSet: {
                  $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
                },
              },
            },
          },
        ])
        .toArray(),
      activityCollection
        .aggregate([
          {
            $match: {
              userId,
              timestamp: { $gte: startDate },
            },
          },
          {
            $group: {
              _id: null,
              totalActivities: { $sum: 1 },
              avgDuration: { $avg: "$duration" },
              uniqueSessions: { $addToSet: "$sessionId" },
            },
          },
        ])
        .toArray(),
    ]);

    const loginData = loginMetrics[0] || { loginCount: 0, uniqueDays: [] };
    const activityData = activityMetrics[0] || {
      totalActivities: 0,
      avgDuration: 0,
      uniqueSessions: [],
    };

    // Calculate engagement score (0-100)
    const loginFrequency = (loginData.uniqueDays.length / days) * 100;
    const activityLevel = Math.min(
      (activityData.totalActivities / days) * 10,
      100,
    );
    const sessionQuality = Math.min(
      (activityData.avgDuration / 60000) * 20,
      100,
    ); // Convert to minutes

    const engagementScore =
      loginFrequency * 0.3 + activityLevel * 0.5 + sessionQuality * 0.2;

    return {
      score: Math.round(engagementScore),
      metrics: {
        loginCount: loginData.loginCount,
        activeDays: loginData.uniqueDays.length,
        totalActivities: activityData.totalActivities,
        avgSessionDuration: activityData.avgDuration,
        uniqueSessions: activityData.uniqueSessions.length,
      },
    };
  }
}
