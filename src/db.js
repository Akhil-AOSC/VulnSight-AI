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

function mongoDbName() {
  return process.env.MONGODB_DB_NAME || 'vulnsight';
}

async function getCollection() {
  const client = await getClient();
  if (!client) return null;
  const collName = process.env.MONGODB_COLLECTION || 'scans';
  return client.db(mongoDbName()).collection(collName);
}

async function getGitConnectionsCollection() {
  const client = await getClient();
  if (!client) return null;
  const collName = process.env.MONGODB_GIT_COLLECTION || 'git_connections';
  return client.db(mongoDbName()).collection(collName);
}

// Encrypted PAT + metadata. Never store the raw token. One document per Git account.
async function saveGitConnectionToMongo(doc) {
  try {
    const coll = await getGitConnectionsCollection();
    if (!coll) return false;
    await coll.replaceOne(
      { id: doc.id, orgId: doc.orgId },
      { ...doc, updatedAt: new Date().toISOString() },
      { upsert: true }
    );
    return true;
  } catch (err) {
    console.warn('[MongoDB Warning] Could not save Git connection:', err.message);
    return false;
  }
}

async function getGitConnectionFromMongo(orgId, id) {
  try {
    const coll = await getGitConnectionsCollection();
    if (!coll) return null;
    return await coll.findOne({ id, orgId });
  } catch (err) {
    console.warn('[MongoDB Warning] Could not load Git connection:', err.message);
    return null;
  }
}

async function listGitConnectionsFromMongo(orgId) {
  try {
    const coll = await getGitConnectionsCollection();
    if (!coll) return null;
    return await coll.find({ orgId }).sort({ createdAt: 1 }).toArray();
  } catch (err) {
    console.warn('[MongoDB Warning] Could not list Git connections:', err.message);
    return null;
  }
}

async function getUsersCollection() {
  const client = await getClient();
  if (!client) return null;
  return client.db(mongoDbName()).collection(process.env.MONGODB_USERS_COLLECTION || 'users');
}

async function saveUserToMongo(doc) {
  try {
    const coll = await getUsersCollection();
    if (!coll) return false;
    await coll.replaceOne(
      { email: doc.email },
      { ...doc, updatedAt: new Date().toISOString() },
      { upsert: true }
    );
    return true;
  } catch (err) {
    console.warn('[MongoDB Warning] Could not save user:', err.message);
    return false;
  }
}

async function getUserFromMongoByEmail(email) {
  try {
    const coll = await getUsersCollection();
    if (!coll) return null;
    return await coll.findOne({ email: String(email || '').trim().toLowerCase() });
  } catch (err) {
    console.warn('[MongoDB Warning] Could not load user:', err.message);
    return null;
  }
}

async function deleteGitConnectionFromMongo(orgId, id) {
  try {
    const coll = await getGitConnectionsCollection();
    if (!coll) return false;
    await coll.deleteOne({ id, orgId });
    return true;
  } catch (err) {
    console.warn('[MongoDB Warning] Could not delete Git connection:', err.message);
    return false;
  }
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
  saveGitConnectionToMongo,
  getGitConnectionFromMongo,
  listGitConnectionsFromMongo,
  deleteGitConnectionFromMongo,
  saveUserToMongo,
  getUserFromMongoByEmail,
};
