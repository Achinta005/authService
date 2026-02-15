import { Request, Response, NextFunction } from 'express';
import { ApiKeyService } from '../services/apiKeyService';

export class ApiKeyMiddleware {
  private apiKeyService: ApiKeyService;

  constructor() {
    this.apiKeyService = new ApiKeyService();
  }

  // Middleware to validate API key and check for specific permission
  requirePermission = (...requiredPermissions: string[]) => {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        const apiKey = req.headers['x-api-key'] as string;

        if (!apiKey) {
          return res.status(401).json({
            success: false,
            message: 'API key is required in x-api-key header',
          });
        }

        // Validate API key
        const result = await this.apiKeyService.validateApiKey(
          apiKey,
          'auth-service',
        );

        if (!result.valid || !result.data) {
          return res.status(401).json({
            success: false,
            message: result.message || 'Invalid API key',
          });
        }

        const scopes = Array.isArray(result.data.scopes)
          ? result.data.scopes
          : [];

        /* ================= PERMISSION CHECK ================= */

        // Always allow admin (super-scope)
        const hasPermission =
          scopes.includes('admin') ||
          requiredPermissions.some((perm) => scopes.includes(perm));

        if (!hasPermission) {
          return res.status(403).json({
            success: false,
            message: `Insufficient permissions. Required any of: ${requiredPermissions.join(
              ', ',
            )}`,
          });
        }

        next();
      } catch (error: any) {
        console.error('❌ [requirePermission] error:', error);

        return res.status(500).json({
          success: false,
          message: 'Internal server error',
        });
      }
    };
  };
}
