import { Router } from 'express';
import { MFAController } from '../controller/MFAController';
import { authenticate } from '../middlewares/authenticate';
import { body } from 'express-validator';
import { validateRequest } from '../middlewares/validateRequest';

const router = Router();
const mfaController = new MFAController();

// All MFA routes require authentication
router.use(authenticate);

// Enroll MFA (Generate QR code)
router.post('/enroll', mfaController.enrollMFA);

// Verify MFA (Complete enrollment)
router.post(
  '/verify',
  [
    body('factorId').notEmpty().withMessage('Factor ID is required'),
    body('code')
      .isLength({ min: 6, max: 6 })
      .withMessage('Code must be 6 digits'),
  ],
  validateRequest,
  mfaController.verifyMFA
);

// Challenge MFA (during login)
router.post(
  '/challenge',
  [body('factorId').notEmpty().withMessage('Factor ID is required')],
  validateRequest,
  mfaController.challengeMFA
);

// Unenroll MFA (Disable)
router.post(
  '/unenroll',
  [body('factorId').notEmpty().withMessage('Factor ID is required')],
  validateRequest,
  mfaController.unenrollMFA
);

// List MFA factors
router.get('/factors', mfaController.listMFAFactors);

export default router;