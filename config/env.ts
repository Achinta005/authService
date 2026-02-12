import dotenv from "dotenv";
dotenv.config();

export const config = {
  nodeEnv: process.env.NODE_ENV || "development",
  port: parseInt(process.env.PORT!),
  apiVersion: process.env.API_VERSION!,

  postgres: {
    host: process.env.POSTGRES_HOST!,
    port: parseInt(process.env.POSTGRES_PORT!),
    username: process.env.POSTGRES_USER!,
    password: process.env.POSTGRES_PASSWORD!,
    database: process.env.POSTGRES_DB!,
  },

  mongodb: {
    uri: process.env.MONGODB_URI!,
  },

  supabase: {
    url: process.env.SUPABASE_URL!,
    anonKey: process.env.SUPABASE_ANON_KEY!,
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY!,
  },

  redis: {
    url: process.env.REDIS_URL!,
  },

  security: {
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || "5"),
    lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || "900"),
  },

  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || "900000"),
    max: parseInt(process.env.RATE_LIMIT_MAX || "100"),
  },

  frontend: {
    url: process.env.FRONTEND_URL!,
  },
};
