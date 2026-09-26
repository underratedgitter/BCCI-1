// api/applicant-auth.js
// Handles applicant password authentication, first-time OTP registration,
// and OTP-driven password reset.

import crypto from 'crypto';
import { redis, KEYS, withRetry } from './_lib/redis.js';
import { getApplicationByEmail } from './_lib/records.js';
import { getAccount, saveAccount, verifyPasswordAsync } from './_lib/accounts.js';
import { sendRaw } from './_lib/email.js';
import {
  applyCors,
  handlePreflight,
  rateLimit,
  tooManyRequests,
  safeEqual,
  clientIp,
  str,
  isEmail,
  esc,
  withErrorHandling,
} from './_lib/http.js';

const SESSION_TTL_SECONDS = 24 * 60 * 60; // 24 hours
const OTP_TTL_SECONDS = 600; // 10 minutes
const MAX_OTP_ATTEMPTS = 5;

// Pre-computed dummy salt & hash to ensure constant-time response for absent accounts (SEC-01)
const DUMMY_SALT = '0123456789abcdef0123456789abcdef';
const DUMMY_HASH = '0123456789abcdef'.repeat(8);

const resetOtpEmail = (code) => `
<div style="font-family:Arial,sans-serif;text-align:center;padding:40px;background:#F1F5F9;">
  <div style="max-width:400px;margin:0 auto;background:#FFF;border-radius:12px;padding:32px;border:1px solid #E2E8F0;">
    <h2 style="color:#0F2C59;margin-bottom:8px;">BCCI Password Reset</h2>
    <p style="color:#64748B;font-size:14px;margin-bottom:24px;">Enter this code to reset your password</p>
    <div style="font-size:36px;font-weight:bold;letter-spacing:12px;color:#0F2C59;background:#F8FAFC;padding:16px;border-radius:8px;border:2px dashed #D4AF37;">${esc(code)}</div>
    <p style="color:#94A3B8;font-size:12px;margin-top:24px;">This code expires in 10 minutes.</p>
    <p style="color:#94A3B8;font-size:11px;margin-top:8px;">If you didn't request a password reset, you can safely ignore this email.</p>
  </div>
</div>`;

async function handler(req, res) {
  applyCors(req, res, 'POST, OPTIONS');
  if (handlePreflight(req, res)) return;

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method not allowed.' });
  }

  const action = str(req.body?.action, 50).toLowerCase();

  // ── 1. LOGIN ──────────────────────────────────────────────────────────
  if (action === 'login') {
    const email = str(req.body?.email, 254).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!isEmail(email)) {
      return res.status(400).json({ success: false, error: 'A valid email address is required.' });
    }
    if (!password) {
      return res.status(400).json({ success: false, error: 'Password is required.' });
    }

    const ip = clientIp(req);
    const ipLimit = await rateLimit(`applicantlogin:ip:${ip}`, { max: 10, windowSec: 900 });
    if (!ipLimit.ok) {
      return tooManyRequests(res, ipLimit.retryAfter, 'Too many login attempts. Please try again later.');
    }
    const emailLimit = await rateLimit(`applicantlogin:email:${email}`, { max: 10, windowSec: 900 });
    if (!emailLimit.ok) {
      return tooManyRequests(res, emailLimit.retryAfter, 'Too many login attempts for this account. Please try again later.');
    }

    const account = await getAccount(email);

    // SEC-01: Uniform response and constant-time verification for all invalid logins:
    // Nonexistent accounts, accounts without password set, and wrong passwords all return 401
    // with identical structure and execute scrypt password hashing to eliminate timing differences.
    if (!account || !account.passwordHash) {
      await verifyPasswordAsync(password, DUMMY_HASH, DUMMY_SALT).catch(() => false);
      return res.status(401).json({ success: false, error: 'Invalid email or password.' });
    }

    if (!await verifyPasswordAsync(password, account.passwordHash, account.salt)) {
      return res.status(401).json({ success: false, error: 'Invalid email or password.' });
    }

    const token = crypto.randomUUID();
    const sessionData = { email, issuedAt: Date.now() };
    await withRetry(() =>
      redis.set(KEYS.applicantSession(token), sessionData, { ex: SESSION_TTL_SECONDS })
    );

    return res.status(200).json({
      success: true,
      session: {
        token,
        email,
        name: email.split('@')[0],
        authenticatedAt: new Date().toISOString(),
        authMethod: 'password',
        expiresIn: SESSION_TTL_SECONDS,
      },
    });
  }

  // ── 2. REGISTER ───────────────────────────────────────────────────────
  if (action === 'register') {
    const email = str(req.body?.email, 254).toLowerCase();
    const code = str(req.body?.code, 12);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!isEmail(email)) {
      return res.status(400).json({ success: false, error: 'A valid email address is required.' });
    }
    if (!code) {
      return res.status(400).json({ success: false, error: 'Verification code is required.' });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters long.' });
    }

    const attempt = await rateLimit(`otpverify:${email}`, { max: MAX_OTP_ATTEMPTS, windowSec: 600 });
    if (!attempt.ok) {
      await redis.del(`bcci:otp:${email}`).catch(() => {});
      return tooManyRequests(res, attempt.retryAfter, 'Too many incorrect attempts. Please request a new verification code.');
    }

    const storedOtp = await withRetry(() => redis.get(`bcci:otp:${email}`));
    if (!storedOtp) {
      return res.status(400).json({
        success: false,
        error: 'That code has expired or was already used. Please request a new one.',
      });
    }

    if (!safeEqual(code, String(storedOtp))) {
      const remaining = Math.max(0, attempt.remaining ?? 0);
      return res.status(400).json({
        success: false,
        error: remaining > 0
          ? `Incorrect code. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
          : 'Too many incorrect attempts. Please request a new verification code.',
      });
    }

    // Atomic single-use claim: only the first concurrent request can claim this OTP
    const claimed = await redis.set(`bcci:otp:claimed:${email}`, '1', { nx: true, ex: 60 });
    if (!claimed) {
      return res.status(400).json({
        success: false,
        error: 'That code has expired or was already used. Please request a new one.',
      });
    }

    // Save account with password hash and salt
    await saveAccount(email, password);

    // Clean up OTP and rate limiter
    await redis.del(`bcci:otp:${email}`).catch(() => {});
    await redis.del(`bcci:rl:otpverify:${email}`).catch(() => {});

    // Issue session token
    const token = crypto.randomUUID();
    const sessionData = { email, issuedAt: Date.now() };
    await withRetry(() =>
      redis.set(KEYS.applicantSession(token), sessionData, { ex: SESSION_TTL_SECONDS })
    );

    return res.status(201).json({
      success: true,
      message: 'Account created successfully.',
      session: {
        token,
        email,
        name: email.split('@')[0],
        authenticatedAt: new Date().toISOString(),
        authMethod: 'password',
        expiresIn: SESSION_TTL_SECONDS,
      },
    });
  }

  // ── 3. FORGOT PASSWORD REQUEST ────────────────────────────────────────
  if (action === 'forgot-password-request') {
    const email = str(req.body?.email, 254).toLowerCase();
    if (!isEmail(email)) {
      return res.status(400).json({ success: false, error: 'A valid email address is required.' });
    }

    const perAddress = await rateLimit(`otpreset:addr:${email}`, { max: 1, windowSec: 60 });
    if (!perAddress.ok) {
      return tooManyRequests(res, perAddress.retryAfter, `Please wait ${perAddress.retryAfter}s before requesting another reset code.`);
    }
    const dailyAddress = await rateLimit(`otpreset:addr:daily:${email}`, { max: 10, windowSec: 86400 });
    if (!dailyAddress.ok) {
      return tooManyRequests(res, dailyAddress.retryAfter, 'Daily reset limit reached for this address. Please try again tomorrow.');
    }
    const perIp = await rateLimit(`otpreset:ip:${clientIp(req)}`, { max: 20, windowSec: 3600 });
    if (!perIp.ok) {
      return tooManyRequests(res, perIp.retryAfter, 'Too many requests from this network. Please try again later.');
    }

    // Verify account or application exists before dispatching mail, but always return uniform response (SEC-01)
    const account = await getAccount(email);
    const legacyApp = !account ? await getApplicationByEmail(email) : null;

    if (account || legacyApp) {
      const otp = crypto.randomInt(100000, 1000000).toString();
      await withRetry(() => redis.set(KEYS.otpReset(email), otp, { ex: OTP_TTL_SECONDS }));
      await redis.del(`bcci:rl:otpresetverify:${email}`).catch(() => {});
      await redis.del(`bcci:otp:reset:claimed:${email}`).catch(() => {});

      const result = await sendRaw({
        to: email,
        subject: 'BCCI Password Reset Code',
        html: resetOtpEmail(otp),
      });

      if (!result.success) {
        await redis.del(KEYS.otpReset(email)).catch(() => {});
        return res.status(502).json({
          success: false,
          error: 'We could not send the password reset email. Please try again in a moment.',
        });
      }
    }

    return res.status(200).json({
      success: true,
      message: 'Password reset code sent to your email.',
    });
  }

  // ── 4. RESET PASSWORD ─────────────────────────────────────────────────
  if (action === 'reset-password') {
    const email = str(req.body?.email, 254).toLowerCase();
    const code = str(req.body?.code, 12);
    const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';

    if (!isEmail(email)) {
      return res.status(400).json({ success: false, error: 'A valid email address is required.' });
    }
    if (!code) {
      return res.status(400).json({ success: false, error: 'Verification code is required.' });
    }
    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters long.' });
    }

    const attempt = await rateLimit(`otpresetverify:${email}`, { max: MAX_OTP_ATTEMPTS, windowSec: 600 });
    if (!attempt.ok) {
      await redis.del(KEYS.otpReset(email)).catch(() => {});
      return tooManyRequests(res, attempt.retryAfter, 'Too many incorrect attempts. Please request a new reset code.');
    }

    const storedOtp = await withRetry(() => redis.get(KEYS.otpReset(email)));
    if (!storedOtp) {
      return res.status(400).json({
        success: false,
        error: 'That code has expired or was already used. Please request a new one.',
      });
    }

    if (!safeEqual(code, String(storedOtp))) {
      const remaining = Math.max(0, attempt.remaining ?? 0);
      return res.status(400).json({
        success: false,
        error: remaining > 0
          ? `Incorrect code. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
          : 'Too many incorrect attempts. Please request a new reset code.',
      });
    }

    // Atomic single-use claim: only the first concurrent request can claim this reset OTP
    const claimed = await redis.set(`bcci:otp:reset:claimed:${email}`, '1', { nx: true, ex: 60 });
    if (!claimed) {
      return res.status(400).json({
        success: false,
        error: 'That code has expired or was already used. Please request a new one.',
      });
    }

    // Upsert account with new password hash and salt
    await saveAccount(email, newPassword);

    // Clean up reset OTP and attempt counter
    await redis.del(KEYS.otpReset(email)).catch(() => {});
    await redis.del(`bcci:rl:otpresetverify:${email}`).catch(() => {});

    // Issue session token
    const token = crypto.randomUUID();
    const sessionData = { email, issuedAt: Date.now() };
    await withRetry(() =>
      redis.set(KEYS.applicantSession(token), sessionData, { ex: SESSION_TTL_SECONDS })
    );

    return res.status(200).json({
      success: true,
      message: 'Password reset successful.',
      session: {
        token,
        email,
        name: email.split('@')[0],
        authenticatedAt: new Date().toISOString(),
        authMethod: 'password',
        expiresIn: SESSION_TTL_SECONDS,
      },
    });
  }

  return res.status(400).json({
    success: false,
    error: 'Invalid or unsupported action.',
  });
}

export default withErrorHandling('ApplicantAuth', handler);
