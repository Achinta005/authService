import multer from "multer";

// Memory storage - file will be available as buffer
const storage = multer.memoryStorage();

// File filter - only allow images
const fileFilter = (req: any, file: Express.Multer.File, cb: any) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Only image files are allowed"), false);
  }
};

// Multer configuration
export const uploadConfig = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1,
  },
  fileFilter: fileFilter,
});