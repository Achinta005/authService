import { MongoClient, Db } from 'mongodb';
import { config } from './env';

let db: Db;
let client: MongoClient;

export const connectMongoDB = async (): Promise<Db> => {
  try {
    client = new MongoClient(config.mongodb.uri);
    await client.connect();
    db = client.db();
    
    // Create indexes for performance
    await createIndexes();
    
    console.log('✅ MongoDB connected');
    return db;
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
};

const createIndexes = async () => {
  // Login logs indexes
  await db.collection('login_logs').createIndex({ userId: 1, createdAt: -1 });
  await db.collection('login_logs').createIndex({ email: 1 });
  await db.collection('login_logs').createIndex({ ipAddress: 1 });
  await db.collection('login_logs').createIndex({ createdAt: -1 });
  
  // Audit logs indexes
  await db.collection('audit_logs').createIndex({ userId: 1, timestamp: -1 });
  await db.collection('audit_logs').createIndex({ action: 1 });
  await db.collection('audit_logs').createIndex({ timestamp: -1 });
  
  // Activity logs indexes
  await db.collection('activity_logs').createIndex({ userId: 1, timestamp: -1 });
  await db.collection('activity_logs').createIndex({ eventType: 1 });
  
  // Security events indexes
  await db.collection('security_events').createIndex({ userId: 1, timestamp: -1 });
  await db.collection('security_events').createIndex({ eventType: 1, severity: 1 });
  await db.collection('security_events').createIndex({ ipAddress: 1 });
  
};

export const getMongoDb = (): Db => {
  if (!db) {
    throw new Error('MongoDB not initialized');
  }
  return db;
};

export const closeMongoConnection = async () => {
  if (client) {
    await client.close();
  }
};