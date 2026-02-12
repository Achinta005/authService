// src/utils/response.ts
import { Response } from 'express';

export class ApiResponse {
  static success(res: Response, data: any, message: string = 'Success', statusCode: number = 200) {
    return res.status(statusCode).json({
      success: true,
      message,
      data,
    });
  }

  static error(res: Response, message: string, statusCode: number = 500, errors?: any) {
    return res.status(statusCode).json({
      success: false,
      message,
      ...(errors && { errors }),
    });
  }

  static created(res: Response, data: any, message: string = 'Created successfully') {
    return this.success(res, data, message, 201);
  }

  static noContent(res: Response) {
    return res.status(204).send();
  }

  static unauthorized(res: Response, message: string = 'Unauthorized') {
    return this.error(res, message, 401);
  }

  static forbidden(res: Response, message: string = 'Forbidden') {
    return this.error(res, message, 403);
  }

  static notFound(res: Response, message: string = 'Not found') {
    return this.error(res, message, 404);
  }

  static badRequest(res: Response, message: string = 'Bad request', errors?: any) {
    return this.error(res, message, 400, errors);
  }
}