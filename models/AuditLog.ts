export interface AuditLog {
  _id?: string;
  userId: string;
  action: string;
  resource: string;
  resourceId?: string;
  changes?: {
    before?: Record<string, any>;
    after?: Record<string, any>;
  };
  ipAddress: string;
  userAgent: string;
  performedBy?: string;
  metadata?: Record<string, any>;
  timestamp: Date;
}