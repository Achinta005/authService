export interface ActivityLog {
  _id?: string;
  userId: string;
  eventType: string;
  eventCategory: string;
  eventLabel?: string;
  eventValue?: number;
  page?: string;
  referrer?: string;
  sessionId: string;
  ipAddress: string;
  userAgent: string;
  duration?: number;
  metadata?: Record<string, any>;
  timestamp: Date;
}