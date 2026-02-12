import "reflect-metadata";
import app from "./app";
import { config } from "./config/env";
import { initializeDatabase } from "./config/db";
import { connectMongoDB } from "./config/mongodb";
import { initRedis, closeRedis } from "./config/redis";
import { RoleService } from "./services/roleService";
import { logger } from "./utils/logger";

const startServer = async () => {
  try {
    // ============ INITIALIZE DATABASES ============
    console.log("🔄 Initializing databases...");

    // PostgreSQL (TypeORM)
    await initializeDatabase();

    // MongoDB
    await connectMongoDB();

    // Redis - now properly awaited
    await initRedis();

    console.log("✅ All databases connected");

    // ============ START SERVER ============
    const PORT = config.port;

    app.listen(PORT, () => {
      console.log("");
      console.log("════════════════════════════════════════════");
      console.log("🚀 AUTH MICROSERVICE STARTED");
      console.log("════════════════════════════════════════════");
      console.log(`📡 Server running on port: ${PORT}`);
      console.log(`🌍 Environment: ${config.nodeEnv}`);
      console.log(`📝 API Version: ${config.apiVersion}`);
      console.log(
        `🔗 Base URL: http://localhost:${PORT}/api/${config.apiVersion}`,
      );
      console.log("════════════════════════════════════════════");
      console.log("");
      console.log("Available endpoints:");
      console.log(`  GET  /api/${config.apiVersion}/health`);
      console.log(`  POST /api/${config.apiVersion}/auth/register`);
      console.log(`  POST /api/${config.apiVersion}/auth/login`);
      console.log(`  POST /api/${config.apiVersion}/auth/logout`);
      console.log(`  GET  /api/${config.apiVersion}/auth/me`);
      console.log("");
    });

    // ============ GRACEFUL SHUTDOWN ============
    process.on("SIGTERM", async () => {
      logger.info("SIGTERM signal received: closing HTTP server");
      await closeRedis();
      process.exit(0);
    });

    process.on("SIGINT", async () => {
      logger.info("SIGINT signal received: closing HTTP server");
      await closeRedis();
      process.exit(0);
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};

startServer();
