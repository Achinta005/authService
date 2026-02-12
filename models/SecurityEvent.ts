export interface SecurityEvent {
  _id?: string;
  userId?: string;
  eventType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  ipAddress: string;
  userAgent: string;
  location?: {
    country?: string;
    city?: string;
  };
  actionTaken?: string;
  resolved: boolean;
  resolvedAt?: Date;
  resolvedBy?: string;
  metadata?: Record<string, any>;
  timestamp: Date;
}