'use strict';

const { MongoClient } = require('mongodb');

let clientPromise = null;
let isConnected = false;
let connectionLogged = false;
let lastMongoError = null;

function getMongoUri() {
  return process.env.MONGODB_URI || '';
}

function isMongoConfigured() {
  return Boolean(getMongoUri().trim());
}

function getMongoStatus() {
  return {
    configured: isMongoConfigured(),
    connected: isConnected,
    error: lastMongoError,
  };
}

async function getClient() {
  const uri = getMongoUri().trim();
  if (!uri) return null;

  if (!clientPromise) {
    const client = new MongoClient(uri, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 8000,
    });
    clientPromise = client.connect().then(() => {
      isConnected = true;
      lastMongoError = null;
      if (!connectionLogged) {
        console.log('[MongoDB] Connected successfully to Atlas cluster.');
        connectionLogged = true;
      }
      return client;
    }).catch((err) => {
      isConnected = false;
      clientPromise = null; // allow retry on next request
      lastMongoError = err.message;
      if (!connectionLogged) {
        console.warn(`[MongoDB Notice] Could not connect to MongoDB Atlas (${err.message}). Using local history storage. Ensure your IP is whitelisted in MongoDB Atlas Network Access.`);
        connectionLogged = true;
      }
      return null;
    });
  }

  return clientPromise;
}

async function getCollection() {
  const client = await getClient();
  if (!client) return null;
  const dbName = process.env.MONGODB_DB_NAME || 'vulnsight';
  const collName = process.env.MONGODB_COLLECTION || 'scans';
  return client.db(dbName).collection(collName);
}

async function saveScanToMongo(scanRecord) {
  try {
    const coll = await getCollection();
    if (!coll) return false;
    await coll.replaceOne(
      { id: scanRecord.id },
      { ...scanRecord, updatedAt: new Date().toISOString() },
      { upsert: true }
    );
    return true;
  } catch (err) {
    console.warn('[MongoDB Warning] Could not save scan to MongoDB:', err.message);
    return false;
  }
}

async function listScansFromMongo() {
  try {
    const coll = await getCollection();
    if (!coll) return null;
    const docs = await coll.find({}).sort({ scannedAt: -1 }).limit(50).toArray();
    return docs.map((s) => ({
      id: s.id,
      scannedAt: s.scannedAt,
      target: s.target,
      projectCount: Array.isArray(s.projects) ? s.projects.length : (s.projectCount || 0),
      summary: s.summary,
      ai: s.ai || null,
      source: 'mongodb',
    }));
  } catch (err) {
    console.warn('[MongoDB Warning] Could not list scans from MongoDB:', err.message);
    return null;
  }
}

async function listFullScansFromMongo(limit = 50) {
  try {
    const coll = await getCollection();
    if (!coll) return null;
    return await coll.find({}).sort({ scannedAt: -1 }).limit(limit).toArray();
  } catch (err) {
    console.warn('[MongoDB Warning] Could not list full scans from MongoDB:', err.message);
    return null;
  }
}

async function getScanFromMongo(id) {
  try {
    const coll = await getCollection();
    if (!coll) return null;
    return await coll.findOne({ id });
  } catch (err) {
    console.warn('[MongoDB Warning] Could not fetch scan from MongoDB:', err.message);
    return null;
  }
}

module.exports = {
  isMongoConfigured,
  getMongoStatus,
  saveScanToMongo,
  listScansFromMongo,
  listFullScansFromMongo,
  getScanFromMongo,
  getClient,
};
