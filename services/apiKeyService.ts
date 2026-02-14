import { AppDataSource } from '../config/db';
import { ApiKey } from '../entities/apiKey';
import { Repository } from 'typeorm';
import * as crypto from 'crypto';

export class ApiKeyService {
  private apiKeyRepo: Repository<ApiKey>;

  constructor() {
    this.apiKeyRepo = AppDataSource.getRepository(ApiKey);
  }

  // Generate a secure API key with service prefix
  private generateApiKey(servicePrefix: string): string {
    const randomBytes = crypto.randomBytes(32).toString('hex');
    return `${servicePrefix}_${randomBytes}`;
  }

  // Create a new API key for a service
  async createApiKey(data: {
    name: string;
    serviceId: string;
    scopes: string[];
    expiresInDays: number;
    description?: string;
  }) {
    // Check if service already has an API key
    const existingKey = await this.apiKeyRepo.findOne({
      where: { serviceId: data.serviceId },
    });

    if (existingKey) {
      throw new Error(`API key already exists for service: ${data.serviceId}`);
    }

    // Generate API key with service prefix (e.g., "user_abc123...")
    const servicePrefix = data.serviceId.split('-')[0];
    const rawKey = this.generateApiKey(servicePrefix);

    // Calculate expiration date
    const expiresAt = new Date(
      Date.now() + data.expiresInDays * 24 * 60 * 60 * 1000,
    );

    const apiKey = this.apiKeyRepo.create({
      name: data.name,
      serviceId: data.serviceId,
      key: rawKey,
      scopes: data.scopes,
      description: data.description,
      expiresAt,
      isActive: true,
    });

    await this.apiKeyRepo.save(apiKey);

    return apiKey;
  }

  // Get all API keys
  async getAllApiKeys() {
    const keys = await this.apiKeyRepo.find({
      order: { createdAt: 'DESC' },
    });
    return keys;
  }

  // Get API key by ID
  async getApiKeyById(keyId: string) {
    const key = await this.apiKeyRepo.findOne({
      where: { id: keyId },
    });

    if (!key) {
      throw new Error('API key not found');
    }

    return key;
  }

  // Verify and validate an API key
  async validateApiKey(rawKey: string) {
    const key = await this.apiKeyRepo.findOne({
      where: { key: rawKey, serviceId: 'auth-service' },
    });

    if (!key) {
      return {
        valid: false,
        message: 'Invalid API key',
      };
    }

    // Check if inactive
    if (!key.isActive) {
      return {
        valid: false,
        message: 'API key is inactive',
      };
    }

    // Check if expired
    if (new Date(key.expiresAt) <= new Date()) {
      return {
        valid: false,
        message: 'API key has expired',
      };
    }

    // Update last used timestamp
    await this.apiKeyRepo.update({ id: key.id }, { lastUsedAt: new Date() });

    return {
      valid: true,
      data: {
        serviceId: key.serviceId,
        scopes: key.scopes,
        permissions: key.scopes, // alias for scopes
        name: key.name,
        expiresAt: key.expiresAt,
      },
    };
  }

  // Delete an API key
  async deleteApiKey(keyId: string) {
    const key = await this.apiKeyRepo.findOne({
      where: { id: keyId },
    });

    if (!key) {
      throw new Error('API key not found');
    }

    await this.apiKeyRepo.delete({ id: keyId });

    return { message: 'API key deleted successfully' };
  }

  // Rotate API key (generate new key for same service)
  async rotateApiKey(keyId: string) {
    const oldKey = await this.getApiKeyById(keyId);

    // Generate new key
    const servicePrefix = oldKey.serviceId.split('-')[0];
    const newRawKey = this.generateApiKey(servicePrefix);

    // Update the key
    await this.apiKeyRepo.update({ id: keyId }, { key: newRawKey });

    return this.getApiKeyById(keyId);
  }
}
