import express, { Application } from "express";
import helmet from "helmet";
import cors from "cors";
import morgan from "morgan";
import { config } from "./config/env";
import router from "./routes";
import { errorHandler } from "./middlewares/errorHandeller";
import { generalLimiter } from "./middlewares/rateLimitter";

const app: Application = express();

// ============ SECURITY MIDDLEWARE ============
app.use(helmet());

// ============ CORS ============
app.use(
  cors({
    origin: config.frontend.url,
    credentials: true,
  }),
);

// ============ BODY PARSER ============
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ============ LOGGING ============
if (config.nodeEnv === "development") {
  app.use(morgan("dev"));
} else {
  app.use(morgan("combined"));
}

// ============ RATE LIMITING ============
app.use(generalLimiter);

// ============ TRUST PROXY ============
app.set("trust proxy", 1);

// ============ ROUTES ============
app.use(`/api/${config.apiVersion}`, router);

// ============ ROOT ENDPOINT ============
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Auth Microservice API",
    version: config.apiVersion,
    documentation: `/api/${config.apiVersion}/health`,
  });
});

// ============ 404 HANDLER ============
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

// ============ ERROR HANDLER ============
app.use(errorHandler);

export default app;
