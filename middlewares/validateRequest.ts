import { validationResult } from "express-validator";
import { Request, Response, NextFunction } from "express";

export const validateRequest = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    console.error("❌ REGISTER VALIDATION FAILED");
    console.error("📥 BODY:", JSON.stringify(req.body, null, 2));
    console.error("🚨 ERRORS:", JSON.stringify(errors.array(), null, 2));

    return res.status(400).json({
      success: false,
      errors: errors.array(),
    });
  }

  next();
};
