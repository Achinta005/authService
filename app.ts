import express, { Application, Request, Response } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import { config } from './config/env';
import router from './routes';
import { errorHandler } from './middlewares/errorHandeller';
import { generalLimiter } from './middlewares/rateLimitter';
import { logger } from './utils/logger';

const app: Application = express();

app.use(helmet());

app.use(
  cors({
    origin: ['http://localhost:3000','https://appsy-ivory.vercel.app'],
    credentials: true,
  }),
);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(
  morgan(config.nodeEnv === 'development' ? 'dev' : 'combined', {
    stream: {
      write: (message: string) => logger.http(message.trim()),
    },
  }),
);

app.use(generalLimiter);

app.set('trust proxy', 1);

app.get('/health', (req: Request, res: Response) => {
  res.json({
    success: true,
    status: 'ok',
    service: 'auth-microservice',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

app.use(`/api/${config.apiVersion}`, router);

app.get('/', (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'Auth Microservice API',
    version: config.apiVersion,
    documentation: `/api/${config.apiVersion}/health`,
  });
});

app.use((req: Request, res: Response) => {
  logger.warn('Route not found', {
    method: req.method,
    path: req.path,
    ip: req.ip,
  });

  res.status(404).json({
    success: false,
    message: 'Route not found',
  });
});

app.use(errorHandler);

export default app;
