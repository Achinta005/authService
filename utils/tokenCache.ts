import { getRedis } from '../config/redis';

const CACHE_TTL = 60;

export const cacheTokenRotation = async (
  oldRefreshToken: string,
  newAccessToken: string,
  newRefreshToken: string
): Promise<void> => {
  try {
    const redis = await getRedis();
    if (!redis) return; // Redis unavailable — skip cache silently

    const key = `token_rotation:${oldRefreshToken}`;
    await redis.setex(
      key,
      CACHE_TTL,
      JSON.stringify({ newAccessToken, newRefreshToken })
    );
  } catch (error) {
    // Never let cache failure break the auth flow
    console.warn('⚠️ Failed to cache token rotation:', error);
  }
};

export const getCachedTokenRotation = async (
  oldRefreshToken: string
): Promise<{ newAccessToken: string; newRefreshToken: string } | null> => {
  try {
    const redis = await getRedis();
    if (!redis) return null;

    const key = `token_rotation:${oldRefreshToken}`;
    const cached = await redis.get(key);
    if (!cached) return null;

    return JSON.parse(cached);
  } catch (error) {
    console.warn('⚠️ Failed to get cached token rotation:', error);
    return null;
  }
};