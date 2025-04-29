require('dotenv').config()

const client = require('./redisClient');

async function isSuspicious(email) {
    const attempts = await client.get(`otp-requests:${email}`) || 0;
    return attempts >= 4; // simple "AI" rule: more than 4 requests looks suspicious
}

module.exports = { isSuspicious };