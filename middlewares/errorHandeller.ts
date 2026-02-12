import { Request, Response, NextFunction } from "express";
import {
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
  ForbiddenException,
  ConflictException,
  InternalServerErrorException,
} from "../utils/exception";

export const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  console.error("Error:", err);

  // Handle custom exceptions
  if (
    err instanceof BadRequestException ||
    err instanceof NotFoundException ||
    err instanceof UnauthorizedException ||
    err instanceof ForbiddenException ||
    err instanceof ConflictException ||
    err instanceof InternalServerErrorException
  ) {
    return res.status((err as any).statusCode).json({
      success: false,
      message: err.message,
      error: err.name,
    });
  }

  // Handle multer errors
  if (err.name === "MulterError") {
    if ((err as any).code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        success: false,
        message: "File size too large. Maximum size is 5MB",
        error: "MulterError",
      });
    }
    return res.status(400).json({
      success: false,
      message: err.message,
      error: "MulterError",
    });
  }

  // Handle generic errors
  return res.status(500).json({
    success: false,
    message: err.message || "Internal server error",
    error: err.name || "Error",
  });
};
