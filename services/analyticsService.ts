import { getMongoDb } from "../config/mongodb";
import { LoginLog } from "../models/loginLogs";
import { AuditLog } from "../models/AuditLog";
import { ActivityLog } from "../models/ActivityLog";
import { SecurityEvent } from "../models/SecurityEvent";

export class AnalyticsService {
  private get db() {
    return getMongoDb();
  }

  // ============ DASHBOARD METRICS ============
  async getDashboardMetrics(startDate: Date, endDate: Date) {
    const loginCollection = this.db.collection("login_logs");
    const activityCollection = this.db.collection("activity_logs");
    const securityCollection = this.db.collection("security_events");

    const [loginStats, activityStats, securityStats, topUsers] =
      await Promise.all([
        // Login statistics
        loginCollection
          .aggregate([
            {
              $match: {
                createdAt: { $gte: startDate, $lte: endDate },
              },
            },
            {
              $facet: {
                total: [{ $count: "count" }],
                successful: [
                  { $match: { success: true } },
                  { $count: "count" },
                ],
                failed: [{ $match: { success: false } }, { $count: "count" }],
                uniqueUsers: [
                  { $match: { success: true } },
                  { $group: { _id: "$userId" } },
                  { $count: "count" },
                ],
                byMethod: [
                  {
                    $group: {
                      _id: "$loginMethod",
                      count: { $sum: 1 },
                    },
                  },
                ],
              },
            },
          ])
          .toArray(),

        // Activity statistics
        activityCollection
          .aggregate([
            {
              $match: {
                timestamp: { $gte: startDate, $lte: endDate },
              },
            },
            {
              $facet: {
                totalEvents: [{ $count: "count" }],
                uniqueUsers: [
                  { $group: { _id: "$userId" } },
                  { $count: "count" },
                ],
                avgDuration: [
                  {
                    $match: { duration: { $exists: true } },
                  },
                  {
                    $group: {
                      _id: null,
                      avgDuration: { $avg: "$duration" },
                    },
                  },
                ],
                topEvents: [
                  {
                    $group: {
                      _id: "$eventType",
                      count: { $sum: 1 },
                    },
                  },
                  { $sort: { count: -1 } },
                  { $limit: 5 },
                ],
              },
            },
          ])
          .toArray(),

        // Security statistics
        securityCollection
          .aggregate([
            {
              $match: {
                timestamp: { $gte: startDate, $lte: endDate },
              },
            },
            {
              $facet: {
                total: [{ $count: "count" }],
                bySeverity: [
                  {
                    $group: {
                      _id: "$severity",
                      count: { $sum: 1 },
                    },
                  },
                ],
                unresolved: [
                  { $match: { resolved: false } },
                  { $count: "count" },
                ],
              },
            },
          ])
          .toArray(),

        // Top active users
        activityCollection
          .aggregate([
            {
              $match: {
                timestamp: { $gte: startDate, $lte: endDate },
              },
            },
            {
              $group: {
                _id: "$userId",
                activityCount: { $sum: 1 },
                lastActive: { $max: "$timestamp" },
              },
            },
            { $sort: { activityCount: -1 } },
            { $limit: 10 },
          ])
          .toArray(),
      ]);

    return {
      logins: loginStats[0],
      activity: activityStats[0],
      security: securityStats[0],
      topUsers,
    };
  }

  // ============ USER COHORT ANALYSIS ============
  async getUserCohortAnalysis(cohortMonth: Date) {
    const activityCollection = this.db.collection("activity_logs");

    // Get users who first became active in the cohort month
    const cohortUsers = await activityCollection
      .aggregate([
        {
          $group: {
            _id: "$userId",
            firstActivity: { $min: "$timestamp" },
          },
        },
        {
          $match: {
            firstActivity: {
              $gte: new Date(
                cohortMonth.getFullYear(),
                cohortMonth.getMonth(),
                1,
              ),
              $lt: new Date(
                cohortMonth.getFullYear(),
                cohortMonth.getMonth() + 1,
                1,
              ),
            },
          },
        },
        {
          $project: {
            userId: "$_id",
            cohortMonth: {
              $dateToString: { format: "%Y-%m", date: "$firstActivity" },
            },
          },
        },
      ])
      .toArray();

    const userIds = cohortUsers.map((u) => u.userId);

    // Track retention for next 12 months
    const retention = await activityCollection
      .aggregate([
        {
          $match: {
            userId: { $in: userIds },
          },
        },
        {
          $group: {
            _id: {
              userId: "$userId",
              month: {
                $dateToString: { format: "%Y-%m", date: "$timestamp" },
              },
            },
          },
        },
        {
          $group: {
            _id: "$_id.month",
            activeUsers: { $sum: 1 },
          },
        },
        {
          $sort: { _id: 1 },
        },
      ])
      .toArray();

    return {
      cohortSize: cohortUsers.length,
      cohortMonth: cohortMonth.toISOString().substring(0, 7),
      retention,
    };
  }

  // ============ FUNNEL ANALYSIS ============
  async getFunnelAnalysis(startDate: Date, endDate: Date) {
    const activityCollection = this.db.collection("activity_logs");

    const funnel = await activityCollection
      .aggregate([
        {
          $match: {
            timestamp: { $gte: startDate, $lte: endDate },
            eventType: {
              $in: [
                "page_view",
                "signup_start",
                "signup_complete",
                "first_login",
                "course_view",
                "course_enroll",
              ],
            },
          },
        },
        {
          $group: {
            _id: {
              userId: "$userId",
              eventType: "$eventType",
            },
          },
        },
        {
          $group: {
            _id: "$_id.eventType",
            uniqueUsers: { $sum: 1 },
          },
        },
        {
          $sort: { uniqueUsers: -1 },
        },
      ])
      .toArray();

    // Calculate drop-off rates
    const funnelSteps = [
      "page_view",
      "signup_start",
      "signup_complete",
      "first_login",
      "course_view",
      "course_enroll",
    ];
    const funnelData = funnelSteps.map((step) => {
      const data = funnel.find((f) => f._id === step);
      return {
        step,
        users: data?.uniqueUsers || 0,
        conversionRate: 0,
        dropOffRate: 0,
      };
    });

    // Calculate conversion rates
    for (let i = 1; i < funnelData.length; i++) {
      const current = funnelData[i].users;
      const previous = funnelData[i - 1].users;
      funnelData[i].conversionRate =
        previous > 0 ? (current / previous) * 100 : 0;
      funnelData[i].dropOffRate =
        previous > 0 ? ((previous - current) / previous) * 100 : 0;
    }

    return funnelData;
  }

  // ============ SESSION ANALYSIS ============
  async getSessionAnalysis(startDate: Date, endDate: Date) {
    const activityCollection = this.db.collection("activity_logs");

    const sessionStats = await activityCollection
      .aggregate([
        {
          $match: {
            timestamp: { $gte: startDate, $lte: endDate },
            sessionId: { $exists: true },
          },
        },
        {
          $group: {
            _id: "$sessionId",
            userId: { $first: "$userId" },
            startTime: { $min: "$timestamp" },
            endTime: { $max: "$timestamp" },
            eventCount: { $sum: 1 },
            totalDuration: { $sum: "$duration" },
          },
        },
        {
          $project: {
            userId: 1,
            sessionDuration: {
              $subtract: ["$endTime", "$startTime"],
            },
            eventCount: 1,
            totalDuration: 1,
          },
        },
        {
          $group: {
            _id: null,
            totalSessions: { $sum: 1 },
            avgSessionDuration: { $avg: "$sessionDuration" },
            avgEventsPerSession: { $avg: "$eventCount" },
            avgActivityDuration: { $avg: "$totalDuration" },
            minSessionDuration: { $min: "$sessionDuration" },
            maxSessionDuration: { $max: "$sessionDuration" },
          },
        },
      ])
      .toArray();

    return sessionStats[0] || {};
  }

  // ============ DEVICE & BROWSER ANALYSIS ============
  async getDeviceBrowserAnalysis(startDate: Date, endDate: Date) {
    const loginCollection = this.db.collection("login_logs");

    const analysis = await loginCollection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: startDate, $lte: endDate },
            success: true,
          },
        },
        {
          $facet: {
            byDevice: [
              {
                $group: {
                  _id: "$device",
                  count: { $sum: 1 },
                  uniqueUsers: { $addToSet: "$userId" },
                },
              },
              {
                $project: {
                  device: "$_id",
                  count: 1,
                  uniqueUsers: { $size: "$uniqueUsers" },
                },
              },
              { $sort: { count: -1 } },
            ],
            byBrowser: [
              {
                $group: {
                  _id: "$browser",
                  count: { $sum: 1 },
                  uniqueUsers: { $addToSet: "$userId" },
                },
              },
              {
                $project: {
                  browser: "$_id",
                  count: 1,
                  uniqueUsers: { $size: "$uniqueUsers" },
                },
              },
              { $sort: { count: -1 } },
            ],
            byOS: [
              {
                $group: {
                  _id: "$os",
                  count: { $sum: 1 },
                  uniqueUsers: { $addToSet: "$userId" },
                },
              },
              {
                $project: {
                  os: "$_id",
                  count: 1,
                  uniqueUsers: { $size: "$uniqueUsers" },
                },
              },
              { $sort: { count: -1 } },
            ],
          },
        },
      ])
      .toArray();

    return analysis[0];
  }

  // ============ TIME-BASED PATTERNS ============
  async getTimeBasedPatterns(startDate: Date, endDate: Date) {
    const activityCollection = this.db.collection("activity_logs");

    const patterns = await activityCollection
      .aggregate([
        {
          $match: {
            timestamp: { $gte: startDate, $lte: endDate },
          },
        },
        {
          $project: {
            hour: { $hour: "$timestamp" },
            dayOfWeek: { $dayOfWeek: "$timestamp" },
            userId: 1,
          },
        },
        {
          $facet: {
            byHour: [
              {
                $group: {
                  _id: "$hour",
                  activityCount: { $sum: 1 },
                  uniqueUsers: { $addToSet: "$userId" },
                },
              },
              {
                $project: {
                  hour: "$_id",
                  activityCount: 1,
                  uniqueUsers: { $size: "$uniqueUsers" },
                },
              },
              { $sort: { hour: 1 } },
            ],
            byDayOfWeek: [
              {
                $group: {
                  _id: "$dayOfWeek",
                  activityCount: { $sum: 1 },
                  uniqueUsers: { $addToSet: "$userId" },
                },
              },
              {
                $project: {
                  dayOfWeek: "$_id",
                  activityCount: 1,
                  uniqueUsers: { $size: "$uniqueUsers" },
                },
              },
              { $sort: { dayOfWeek: 1 } },
            ],
          },
        },
      ])
      .toArray();

    return patterns[0];
  }

  // ============ REAL-TIME ANALYTICS ============
  async getRealTimeAnalytics() {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);

    const activityCollection = this.db.collection("activity_logs");
    const loginCollection = this.db.collection("login_logs");

    const [activeUsers, recentLogins, recentActivity] = await Promise.all([
      // Active users in last 5 minutes
      activityCollection
        .aggregate([
          {
            $match: {
              timestamp: { $gte: fiveMinutesAgo },
            },
          },
          {
            $group: {
              _id: "$userId",
              lastActivity: { $max: "$timestamp" },
              activityCount: { $sum: 1 },
            },
          },
          { $count: "count" },
        ])
        .toArray(),

      // Recent logins
      loginCollection
        .find({
          createdAt: { $gte: fiveMinutesAgo },
          success: true,
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .toArray(),

      // Recent activity
      activityCollection
        .find({
          timestamp: { $gte: fiveMinutesAgo },
        })
        .sort({ timestamp: -1 })
        .limit(20)
        .toArray(),
    ]);

    return {
      activeUserCount: activeUsers[0]?.count || 0,
      recentLogins,
      recentActivity,
    };
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

  async getAllSecurityEvents() {
    const collection = this.db.collection<SecurityEvent>("security_events");

    const results = await collection
      .aggregate([
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
                resolved: "$resolved",
                resolvedAt: "$resolvedAt",
              },
            },
          },
        },
        {
          $sort: {
            _id: 1,
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
