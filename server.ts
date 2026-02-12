import "reflect-metadata";
import app from "./app";
import { config } from "./config/env";
import { initializeDatabase } from "./config/db";
import { connectMongoDB } from "./config/mongodb";
import { initRedis, closeRedis } from "./config/redis";
import { logger } from "./utils/logger";

const startServer = async () => {
  try {
    logger.info("Initializing databases...");

    await initializeDatabase();
    await connectMongoDB();
    await initRedis();

    logger.info("All databases connected successfully");

    const PORT = config.port;

    app.listen(PORT, () => {
      logger.info("Auth microservice started", {
        port: PORT,
        environment: config.nodeEnv,
        apiVersion: config.apiVersion,
        baseUrl: `http://localhost:${PORT}/api/${config.apiVersion}`,
      });

      logger.debug("Available endpoints", {
        endpoints: [
          `GET  /api/${config.apiVersion}/health`,
          `POST /api/${config.apiVersion}/auth/register`,
          `POST /api/${config.apiVersion}/auth/login`,
          `POST /api/${config.apiVersion}/auth/logout`,
          `GET  /api/${config.apiVersion}/auth/me`,
        ],
      });
    });

    process.on("SIGTERM", async () => {
      logger.info("SIGTERM signal received: closing server");
      await closeRedis();
      process.exit(0);
    });

    process.on("SIGINT", async () => {
      logger.info("SIGINT signal received: closing server");
      await closeRedis();
      process.exit(0);
    });
  } catch (error) {
    logger.error("Failed to start server", { error });
    process.exit(1);
  }
};

startServer();
