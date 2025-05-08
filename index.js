require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const axios = require('axios');

const { RateLimiterRedis } = require('rate-limiter-flexible');
const client = require('./redisClient');
const { generateOTP, verifyOTP } = require('./otpService');
const { isSuspicious } = require('./aiService');

const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');

require('dotenv').config();

const app = express();
app.use(bodyParser.json());
app.use(helmet());

const limiter = new RateLimiterRedis({
    storeClient: client,
    keyPrefix: 'rateLimiter',
    points: process.env.MAX_OTP_REQUESTS || 5, // Max 5 OTP requests
    duration: 60 * 10, // per 10 minutes
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
});

async function sendOtpViaWhatsApp(phoneNumber, otp) {
    try {

        const payload = new URLSearchParams();
        payload.append('apiKey', process.env.WA_KEY);
        payload.append('phone', phoneNumber);
        payload.append('message', `Your OTP code is: ${otp}`);

        const response = await axios.post(`${process.env.WA_HOST}api/sendMessage`, payload.toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
    } catch (error) {
        console.error('WhatsApp OTP sending failed', error.response?.data || error.message);
        throw new Error('Failed to send WhatsApp message');
    }
}

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePhone(phone) {
    const re = /^\+?[1-9]\d{7,14}$/; // simple E.164 format check
    return re.test(phone);
}

// ===== ROUTES =====
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.use((req, res, next) => {
    if (req.path.startsWith('/dashboard')) {
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== process.env.ADMIN_API_KEY) {
            return res.status(403).json({ message: 'Forbidden' });
        }
    }
    next();
});

app.get('/dashboard', async (req, res) => {
    try {
        const keys = await client.keys('*');

        const otpKeys = keys.filter(key => key.startsWith('otp:') && !key.startsWith('otp-requests:') && !key.startsWith('otp-failures:'));
        const requestKeys = keys.filter(key => key.startsWith('otp-requests:'));
        const failureKeys = keys.filter(key => key.startsWith('otp-failures:'));

        // Fetch counts
        const activeOtps = otpKeys.map(key => key.replace('otp:', ''));

        const requestCounts = await Promise.all(requestKeys.map(async (key) => {
            const count = await client.get(key);
            return { target: key.replace('otp-requests:', ''), count: parseInt(count) };
        }));

        const failureCounts = await Promise.all(failureKeys.map(async (key) => {
            const count = await client.get(key);
            return { target: key.replace('otp-failures:', ''), count: parseInt(count) };
        }));

        // Find top 5 by requests
        const topRequesters = requestCounts.sort((a, b) => b.count - a.count).slice(0, 5);

        // Find top 5 by failures
        const topFailures = failureCounts.sort((a, b) => b.count - a.count).slice(0, 5);

        // Check suspicious users
        const suspiciousTargets = [];
        for (const user of [...new Set([...topRequesters, ...topFailures])]) {
            if (await isSuspicious(user.target)) {
                suspiciousTargets.push(user.target);
            }
        }

        res.status(200).json({
            activeOtps,
            topRequesters,
            topFailures,
            suspiciousTargets
        });

    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ message: 'Failed to load dashboard' });
    }
});

app.post('/send-otp', async (req, res) => {
    const { target } = req.body;

    if (!target) {
        return res.status(400).json({ message: 'Missing target' });
    }

    const isEmail = validateEmail(target);
    const isPhone = validatePhone(target);

    if (!isEmail && !isPhone) {
        return res.status(400).json({ message: 'Invalid target: must be valid email or phone number' });
    }

    try {
        await limiter.consume(target); // Rate limit by email/phone

        const otp = await generateOTP(target);

        if (isEmail) {
            await transporter.sendMail({
                from: process.env.EMAIL,
                to: target,
                subject: 'Your OTP Code',
                text: `Your OTP is ${otp}`
            });
        } else if (isPhone) {
            await sendOtpViaWhatsApp(target, otp);
        }

        await client.incr(`otp-requests:${target}`);
        await client.expire(`otp-requests:${target}`, 600);

        res.status(200).json({ message: `OTP sent to ${isEmail ? 'email' : 'whatsapp'}` });
    } catch (error) {
        if (error instanceof Error) {
            console.error(error);
            return res.status(500).json({ message: 'Internal Server Error' });
        } else {
            return res.status(429).json({ message: 'Too many OTP requests. Please try later.' });
        }
    }
});

app.post('/verify-otp', async (req, res) => {
    const { target, otp } = req.body;
    console.log(`target ${target}`);
    console.log(`otp ${otp}`);
    const valid = await verifyOTP(target, otp);

    if (valid) {
        res.status(200).json({ status: 'success', message: 'OTP Verified Successfully!' });
    } else {
        res.status(400).json({ status: 'error', message: 'Invalid or Expired OTP' });
    }
});

app.get('/recommendation', async (req, res) => {
    const { target } = req.query;

    if (!target) {
        return res.status(400).json({ message: 'Missing target' });
    }

    const [failureCount, requestCount] = await Promise.all([
        client.get(`otp-failures:${target}`),
        client.get(`otp-requests:${target}`)
    ]);

    const suspicious = await isSuspicious(target);

    let recommendations = [];

    if (failureCount && parseInt(failureCount) >= 3) {
        recommendations.push('High number of OTP verification failures. Consider temporarily locking the account.');
    }

    if (requestCount && parseInt(requestCount) >= 5) {
        recommendations.push('High number of OTP requests. Consider stricter verification like CAPTCHA.');
    }

    if (suspicious) {
        recommendations.push('Suspicious behavior detected by AI model. Consider flagging the user for manual review.');
    }

    if (recommendations.length === 0) {
        recommendations.push('User behavior is normal. No action needed.');
    }

    res.status(200).json({ recommendations });
});

app.get('/logs', async (req, res) => {
    try {
        const db = await connectMongo();
        const logs = await db.collection('logs').find().sort({ timestamp: -1 }).limit(100).toArray();
        res.json(logs);
    } catch (err) {
        res.status(500).json({ message: 'Failed to load logs' });
    }
});

app.get('/logs/export', async (req, res) => {
    try {
        const db = await connectMongo();
        const logs = await db.collection('logs').find().toArray();

        const parser = new Parser();
        const csv = parser.parse(logs);

        res.header('Content-Type', 'text/csv');
        res.attachment('otp-logs.csv');
        return res.send(csv);
    } catch (err) {
        res.status(500).json({ message: 'Export failed' });
    }
});

// ===== SERVER START =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});