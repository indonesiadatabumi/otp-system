const fs = require('fs');
const path = require('path');
const connectMongo = require('../db/mongo');

const logFile = path.join(__dirname, '../logs/otp.log');

async function logRequest(user, action, otp, success = null) {
    const timestamp = new Date().toISOString();
    let line = `[${timestamp}] ${action.toUpperCase()} - ${user} - OTP: ${otp}`;
    if (success !== null) line += ` - SUCCESS: ${success}`;

    // File log
    fs.appendFile(logFile, line + '\n', err => {
        if (err) console.error('Log write error:', err);
    });

    // MongoDB log
    const db = await connectMongo();
    await db.collection('logs').insertOne({
        timestamp: new Date(),
        user,
        action,
        otp,
        success
    });
}

module.exports = { logRequest };
