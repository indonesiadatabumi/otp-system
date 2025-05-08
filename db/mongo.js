const { MongoClient } = require('mongodb');
require('dotenv').config();

const client = new MongoClient(process.env.MONGODB_URL);
let db;

async function connectMongo() {
    if (!db) {
        await client.connect();
        db = client.db(process.env.MONGODB_NAME);
        console.log('✅ MongoDB connected');
    }
    return db;
}

module.exports = connectMongo;