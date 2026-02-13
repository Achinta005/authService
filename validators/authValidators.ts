// src/validators/authValidators.ts
import { NextFunction } from "express";
import { body } from "express-validator";

export const logRegisterPayload = (
  req: Request,
  _res: Response,
  next: NextFunction,
) => {
  console.log("🧾 REGISTER RAW BODY:", JSON.stringify(req.body, null, 2));
  next();
};

export const registerValidator = [
  body("email")
    .isEmail()
    .withMessage("Please provide a valid email")
    .normalizeEmail(),
  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage("Password must contain uppercase, lowercase, and number"),
  body("fullName")
    .optional()
    .trim()
    .isLength({ min: 2 })
    .withMessage("Full name must be at least 2 characters"),
  body("role")
    .optional()
    .isIn(["student", "instructor","admin",'user'])
    .withMessage("Invalid role"),
];

export const loginValidator = [
  body("email").isEmail().withMessage("Please provide a valid email"),
  body("password").notEmpty().withMessage("Password is required"),
];

export const forgotPasswordValidator = [
  body("email").isEmail().withMessage("Please provide a valid email"),
];

export const resetPasswordValidator = [
  body("token").notEmpty().withMessage("Reset token is required"),
  body("newPassword")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage("Password must contain uppercase, lowercase, and number"),
];

export const magicLinkValidator = [
  body("email").isEmail().withMessage("Please provide a valid email"),
];

// src/validators/userValidators.ts
export const updateProfileValidator = [
  body("fullName")
    .optional()
    .trim()
    .isLength({ min: 2 })
    .withMessage("Full name must be at least 2 characters"),
  body("phoneNumber")
    .optional()
    .isMobilePhone("any")
    .withMessage("Invalid phone number"),
  body("bio")
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage("Bio must not exceed 500 characters"),
  body("location").optional().trim(),
  body("username")
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage("Username must be between 3 and 30 characters")
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage(
      "Username can only contain letters, numbers, underscores, and hyphens",
    ),
  body("email") // Added - you're sending this field
    .optional()
    .isEmail()
    .withMessage("Invalid email address")
    .normalizeEmail(),
];

export const updatePreferencesValidator = [
  body("theme")
    .optional()
    .isIn(["light", "dark", "auto"])
    .withMessage("Theme must be light, dark, or auto"),
  body("visibility")
    .optional()
    .isIn(["public", "private", "friends"])
    .withMessage("Invalid visibility setting"),
  body("pushNotifications")
    .optional()
    .isBoolean()
    .withMessage("Push notification must be a boolean"),
  body("emailNotifications")
    .optional()
    .isBoolean()
    .withMessage("Email alert must be a boolean"),
];
