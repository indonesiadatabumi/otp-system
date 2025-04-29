require('dotenv').config()

const { loadavg } = require('os');
const client = require('./redisClient');
const crypto = require('crypto');

const OTP_EXPIRY = process.env.OTP_EXPIRY_SECONDS || 300; // 5 min default

async function generateOTP(email) {
    const otp = crypto.randomInt(100000, 999999).toString();
    await client.set(`otp:${email}`, otp, { EX: OTP_EXPIRY });
    return otp;
}

async function verifyOTP(emailOrPhone, otpInput) {
    console.log(`otp:${emailOrPhone}`);
    const otpStored = await client.get(`otp:${emailOrPhone}`);
    console.log('otpStored', otpStored);
    if (otpStored && otpStored === otpInput) {
        await client.del(`otp:${emailOrPhone}`);
        await client.del(`otp-failures:${emailOrPhone}`); // reset failures
        return true;
    } else {
        // Track failed attempts
        await client.incr(`otp-failures:${emailOrPhone}`);
        await client.expire(`otp-failures:${emailOrPhone}`, 600); // failures expire after 10 min
        return false;
    }
}


module.exports = { generateOTP, verifyOTP };