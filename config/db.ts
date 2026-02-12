import { DataSource } from "typeorm";
import { config } from "./env";
import { UserProfile } from "../entities/uerProfile";
import { Role } from "../entities/role";
import { Permission } from "../entities/permission";
import { UserRole } from "../entities/userRole";
import { ApiKey } from "../entities/apiKey";
import { UserPreferences } from "../entities/userPreference";

export const AppDataSource = new DataSource({
  type: "postgres",
  host: config.postgres.host,
  port: config.postgres.port,
  username: config.postgres.username,
  password: config.postgres.password,
  database: config.postgres.database,
  synchronize: config.nodeEnv === "development",
  logging: ["error", "warn"],
  entities: [UserProfile, Role, Permission, UserRole, ApiKey, UserPreferences],
  migrations: [],
  subscribers: [],
});

export const initializeDatabase = async () => {
  try {
    await AppDataSource.initialize();
    console.log("✅ PostgreSQL connected via TypeORM");
  } catch (error) {
    console.error("❌ PostgreSQL connection error:", error);
    process.exit(1);
  }
};
