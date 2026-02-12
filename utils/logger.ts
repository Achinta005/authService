import winston from "winston";
import path from "path";
import { config } from "../config/env";

const isProduction = config.nodeEnv === "production";

const customLevels = {
  levels: {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    debug: 4,
  },
  colors: {
    error: "red",
    warn: "yellow",
    info: "green",
    http: "magenta",
    debug: "blue",
  },
};

winston.addColors(customLevels.colors);

const customFormat = winston.format.printf(
  ({ level, message, timestamp, service, ...metadata }) => {
    let msg = `${timestamp} [${service}] ${level}: ${message}`;

    if (Object.keys(metadata).length > 0) {
      msg += ` ${JSON.stringify(metadata)}`;
    }

    return msg;
  },
);

const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  customFormat,
);

const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
);

const transports: winston.transport[] = [];

if (!isProduction) {
  transports.push(
    new winston.transports.Console({
      format: consoleFormat,
    }),
  );
}

if (isProduction) {
  transports.push(
    new winston.transports.File({
      filename: path.join("logs", "error.log"),
      level: "error",
      maxsize: 5242880,
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join("logs", "combined.log"),
      maxsize: 5242880,
      maxFiles: 5,
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
      ),
    }),
  );
}

export const logger = winston.createLogger({
  levels: customLevels.levels,
  level: isProduction ? "http" : "debug",
  format: fileFormat,
  defaultMeta: {
    service: "auth-microservice",
    environment: config.nodeEnv,
  },
  transports,
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join("logs", "exceptions.log"),
      maxsize: 5242880,
      maxFiles: 3,
    }),
  ],
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join("logs", "rejections.log"),
      maxsize: 5242880,
      maxFiles: 3,
    }),
  ],
  exitOnError: false,
});

logger.info("Logger initialized", {
  level: logger.level,
  environment: config.nodeEnv,
});