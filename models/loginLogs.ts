export interface LoginLog {
  _id?: string;
  userId: string;
  email: string;
  loginMethod: 'email' | 'oauth' | 'magic_link' | 'phone';
  provider?: string;
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