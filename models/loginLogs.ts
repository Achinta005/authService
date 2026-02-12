// src/models/LoginLog.ts
export interface LoginLog {
  _id?: string;
  userId: string;
  email: string;
  loginMethod: 'email' | 'oauth' | 'magic_link' | 'phone';
  provider?: string; // google, github, etc.
  success: boolean;
  failureReason?: string;
  ipAddress: string;
  userAgent: string;
  device: string;
  browser: string;
  os: string;
  location?: {
    country?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
  };
  mfaUsed: boolean;
  sessionId?: string;
  createdAt: Date;
}

// src/models/AuditLog.ts
export interface AuditLog {
  _id?: string;
  userId: string;
  action: string; // user.created, role.assigned, password.changed, etc.
  resource: string; // user, role, permission, etc.
  resourceId?: string;
  changes?: {
    before?: Record<string, any>;
    after?: Record<string, any>;
  };
  ipAddress: string;
  userAgent: string;
  performedBy?: string; // Admin who performed the action
  metadata?: Record<string, any>;
  timestamp: Date;
}

// src/models/ActivityLog.ts
export interface ActivityLog {
  _id?: string;
  userId: string;
  eventType: string; // page_view, api_call, feature_usage, etc.
  eventCategory: string; // navigation, interaction, transaction
  eventLabel?: string;
  eventValue?: number;
  page?: string;
  referrer?: string;
  sessionId: string;
  ipAddress: string;
  userAgent: string;
  duration?: number; // milliseconds
  metadata?: Record<string, any>;
  timestamp: Date;
}

// src/models/SecurityEvent.ts
export interface SecurityEvent {
  _id?: string;
  userId?: string;
  eventType: string; // suspicious_login, account_lockout, mfa_failed, etc.
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  ipAddress: string;
  userAgent: string;
  location?: {
    country?: string;
    city?: string;
  };
  actionTaken?: string; // account_locked, notification_sent, etc.
  resolved: boolean;
  resolvedAt?: Date;
  resolvedBy?: string;
  metadata?: Record<string, any>;
  timestamp: Date;
}