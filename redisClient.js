require('dotenv').config()

const redis = require('redis');
const client = redis.createClient({ url: process.env.REDIS_URL });

client.on('error', (err) => console.error('Redis Client Error', err));
client.connect();
client.select(parseInt(process.env.REDIS_DB || '0', 10));

module.exports = client;