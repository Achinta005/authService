// src/services/AnalyticsService.ts
import { getMongoDb } from "../config/mongodb";
import { LogService } from "./logService";

export class AnalyticsService {
  private get db() {
    return getMongoDb();
  }
  private logService = new LogService();

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
}
