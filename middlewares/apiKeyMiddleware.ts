import { Request, Response, NextFunction } from "express";
import axios from "axios";

declare global {
  namespace Express {
    interface Request {
      apiKey?: any;
    }
  }
}

export class ApiKeyMiddleware {
  requirePermission = (...requiredPermissions: string[]) => {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        const apiKey = req.headers["x-api-key"] as string;

        if (!apiKey) {
          return res.status(401).json({
            success: false,
            message: "API key is required in x-api-key header",
          });
        }

        const { data } = await axios.post(
          `${process.env.LOG_SERVICE_URL}/api/valid`,
          { apiKey, serviceId: "auth-service" },
          {
            headers: {
              "Content-Type": "application/json",
              "x-api-key": process.env.LOG_MICROSERVICE_API_KEY,
            },
            timeout: 5000,
          }
        );

        if (!data.success || !data.data) {
          return res.status(401).json({
            success: false,
            message: data.message || "Invalid API key",
          });
        }

        const scopes = Array.isArray(data.data.scopes) ? data.data.scopes : [];

        const hasPermission =
          scopes.includes("admin") ||
          requiredPermissions.some((perm) => scopes.includes(perm));

        if (!hasPermission) {
          return res.status(403).json({
            success: false,
            message: `Insufficient permissions. Required any of: ${requiredPermissions.join(", ")}`,
          });
        }

        req.apiKey = data.data;
        next();
      } catch (error: any) {
        if (error.response) {
          return res.status(401).json({
            success: false,
            message: error.response.data?.message || "Invalid API key",
          });
        }
        return res.status(500).json({
          success: false,
          message: "Internal server error",
        });
      }
    };
  };
}