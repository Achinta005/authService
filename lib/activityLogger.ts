import axios from 'axios';

const post = async (path: string, payload: Record<string, any>): Promise<void> => {
  try {
    await axios.post(`${process.env.LOG_SERVICE_URL}${path}`, payload, {
      headers: {
        'x-api-key': process.env.LOG_MICROSERVICE_API_KEY,
        'Content-Type': 'application/json',
      },
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    console.error(`[LogService] Failed to log to ${path}:`, errorMessage);
  }
};

export class LoggerService {
  createActivityLog = (payload: Record<string, any>) =>
    post('/log/create-activity-log', payload);

  createLoginLog = (payload: Record<string, any>) =>
    post('/log/create-login-log', payload);

  createAuditLog = (payload: Record<string, any>) =>
    post('/log/create-audit-log', payload);

  createSecurityEvent = (payload: Record<string, any>) =>
    post('/log/create-security-event', payload);
}


// .env 
// LOG_SERVICE_URL
// LOG_MICROSERVICE_API_KEY
// No auth headers