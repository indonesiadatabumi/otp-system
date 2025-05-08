require('dotenv').config()

const { loadavg } = require('os');
const client = require('./redisClient');
const crypto = require('crypto');
const { logRequest } = require('./utils/logger');
const { encrypt, decrypt } = require('./utils/crypto');


const OTP_EXPIRY = process.env.OTP_EXPIRY_SECONDS || 300; // 5 min default

/**
 * Generates a new OTP for the given target and stores it in Redis.
 *
 * @param {string} target - the target (email or phone number) for which the OTP is generated
 * @return {string} the generated OTP
 */
async function generateOTP(target) {
    const otp = crypto.randomInt(100000, 999999).toString();
    const encryptedOtp = encrypt(otp);

    await client.set(`otp:${target}`, encryptedOtp, { EX: OTP_EXPIRY });
    logRequest(target, 'send', otp);
    return otp;
}

/**
 * Verifies the OTP for a given email or phone number.
 *
 * @param {string} emailOrPhone - The email address or phone number associated with the OTP.
 * @param {string} otpInput - The OTP input provided by the user for verification.
 * @returns {Promise<boolean>} - Returns a promise that resolves to true if the OTP is valid, otherwise false.
 *
 * If the OTP is valid, it is deleted from the store along with any failure records. 
 * If invalid, the failure count is incremented and set to expire after 10 minutes.
 */

async function verifyOTP(emailOrPhone, otpInput) {
    const otpStored = await client.get(`otp:${emailOrPhone}`);
    const realOtp = decrypt(otpStored);
    
    console.log(`realOtp ${realOtp}`);
    console.log(`otpInput ${otpInput}`);

    const isMatch = realOtp === otpInput;

    logRequest(emailOrPhone, 'verify', otpInput, isMatch);

    if (isMatch) {
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