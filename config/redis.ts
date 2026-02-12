import Redis from "ioredis";
import { config } from "./env";

let redisInstance: Redis | null = null;
let isConnecting = false;
let connectionPromise: Promise<void> | null = null;

export const getRedis = async (): Promise<Redis | null> => {
  // If already connected, return immediately
  if (redisInstance && redisInstance.status === 'ready') {
    return redisInstance;
  }

  // If connection in progress, wait for it
  if (isConnecting && connectionPromise) {
    await connectionPromise;
    return redisInstance;
  }

  // Check if Redis URL is configured
  if (!config.redis.url) {
    console.warn('⚠️ REDIS_URL not configured, skipping Redis connection');
    return null;
  }

  // Start new connection
  isConnecting = true;
  connectionPromise = connect();

  try {
    await connectionPromise;
    return redisInstance;
  } catch (error) {
    console.warn('⚠️ Redis unavailable, application will continue without caching');
    return null;
  } finally {
    isConnecting = false;
  }
};

const connect = (): Promise<void> => {
  return new Promise((resolve, reject) => {
    console.log('🔄 Connecting to Redis...');

    // Detect if it's cloud Redis (similar to your NestJS version)
    const isCloudRedis =
      !config.redis.url.includes('localhost') && 
      !config.redis.url.includes('127.0.0.1');

    redisInstance = new Redis(config.redis.url, {
      tls: isCloudRedis ? {} : undefined, // ← KEY FIX from your NestJS code
      maxRetriesPerRequest: 1,
      enableReadyCheck: true,
      connectTimeout: 10000,
      lazyConnect: false,
      retryStrategy: (times) => {
        if (times > 1) {
          console.error('❌ Redis connection failed');
          return null;
        }
        return 100;
      },
    });

    let resolved = false;

    redisInstance.once('ready', () => {
      if (!resolved) {
        console.log('✅ Redis connected successfully');
        resolved = true;
        resolve();
      }
    });

    redisInstance.on('error', (err) => {
      console.error(`❌ Redis error: ${err.message}`);
      if (!resolved) {
        resolved = true;
        reject(err);
      }
    });

    redisInstance.on('close', () => {
      if (redisInstance) {
        console.warn('⚠️ Redis connection closed unexpectedly');
      }
    });

    redisInstance.on('reconnecting', () => {
      console.log('🔄 Redis reconnecting...');
    });

    // Timeout after 10 seconds
    setTimeout(() => {
      if (!resolved) {
        const error = new Error('Redis connection timeout');
        console.error('❌ Redis connection timeout');
        resolved = true;
        reject(error);
      }
    }, 10000);
  });
};

export const closeRedis = async (): Promise<void> => {
  if (redisInstance) {
    console.log('🔌 Disconnecting Redis...');
    const client = redisInstance;
    redisInstance = null;
    await client.quit();
    connectionPromise = null;
    isConnecting = false;
  }
};

export const isRedisConnected = (): boolean => {
  return redisInstance?.status === "ready";
};

// Don't auto-initialize - let calling code do it
export const initRedis = async (): Promise<Redis | null> => {
  return await getRedis();
};