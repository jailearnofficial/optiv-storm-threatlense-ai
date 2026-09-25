import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { mailer, SendMailResult } from './mailer.js';

export interface StoredUser {
  id: string;
  email: string;
  displayName: string;
  passwordHash: string;
  createdAt: string;
  lastLoginAt: string;
  role: string;
}

interface PendingRegistration {
  email: string;
  passwordHash: string;
  displayName: string;
  code: string;
  createdAt: number;
  expiresAt: number;
  attempts: number;
}

interface PendingPasswordReset {
  email: string;
  code: string;
  createdAt: number;
  expiresAt: number;
  attempts: number;
}

export function isAllowedEmail(email?: string | null): boolean {
  if (!email) return false;
  const clean = email.trim().toLowerCase();
  return clean.endsWith('@optiv.com') || clean.endsWith('@gmail.com');
}

class UserAuthManager {
  private usersPath: string;
  private users: StoredUser[] = [];
  private pendingRegistrations: Map<string, PendingRegistration> = new Map();
  private pendingResets: Map<string, PendingPasswordReset> = new Map();

  constructor() {
    const dataDir = path.resolve(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      try {
        fs.mkdirSync(dataDir, { recursive: true });
      } catch (err) {
        console.error('Failed to create data dir for auth:', err);
      }
    }
    this.usersPath = path.resolve(dataDir, 'users.json');
    this.loadUsers();
  }

  private loadUsers() {
    try {
      if (fs.existsSync(this.usersPath)) {
        const raw = fs.readFileSync(this.usersPath, 'utf8');
        this.users = JSON.parse(raw);
      } else {
        this.users = [];
        this.saveUsers();
      }
    } catch (e) {
      console.error('Error loading users.json:', e);
      this.users = [];
    }
  }

  private saveUsers() {
    try {
      fs.writeFileSync(this.usersPath, JSON.stringify(this.users, null, 2), 'utf8');
    } catch (e) {
      console.error('Error saving users.json:', e);
    }
  }

  private generate6DigitCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  private hashPassword(password: string): string {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
  }

  private verifyPassword(password: string, storedHash: string): boolean {
    const [salt, key] = storedHash.split(':');
    if (!salt || !key) return false;
    const calcHash = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(key, 'hex'), Buffer.from(calcHash, 'hex'));
  }

  /**
   * Step 1 of Registration: Send 6-digit verification code to email
   */
  public async initiateRegistration(
    email: string,
    pass: string,
    name?: string
  ): Promise<{ message: string; email: string; mailStatus: SendMailResult }> {
    const cleanEmail = email.trim().toLowerCase();
    if (!isAllowedEmail(cleanEmail)) {
      throw new Error('Access Denied: Only @optiv.com or @gmail.com email addresses are permitted.');
    }

    if (!pass || pass.length < 6) {
      throw new Error('Security requirement: Password must be at least 6 characters.');
    }

    const existing = this.users.find((u) => u.email.toLowerCase() === cleanEmail);
    if (existing) {
      throw new Error('An account with this email address already exists. Please switch to Sign In.');
    }

    const code = this.generate6DigitCode();
    const now = Date.now();
    const expiresAt = now + 10 * 60 * 1000; // 10 minutes

    const passwordHash = this.hashPassword(pass);
    const displayName =
      name && name.trim().length > 0
        ? name.trim().substring(0, 64)
        : cleanEmail.split('@')[0];

    this.pendingRegistrations.set(cleanEmail, {
      email: cleanEmail,
      passwordHash,
      displayName,
      code,
      createdAt: now,
      expiresAt,
      attempts: 0
    });

    const mailStatus = await mailer.sendVerificationCode(cleanEmail, code, 'registration');

    return {
      message: mailStatus.sentViaSmtp
        ? `A 6-digit verification code has been dispatched to ${cleanEmail}. Please check your inbox.`
        : `A verification code has been generated for ${cleanEmail}.`,
      email: cleanEmail,
      mailStatus
    };
  }

  /**
   * Step 2 of Registration: Verify 6-digit code and create user account
   */
  public confirmRegistration(
    email: string,
    inputCode: string
  ): { id: string; email: string; displayName: string } {
    const cleanEmail = email.trim().toLowerCase();
    const pending = this.pendingRegistrations.get(cleanEmail);

    if (!pending) {
      throw new Error('No pending registration found for this email, or the session expired. Please register again.');
    }

    if (Date.now() > pending.expiresAt) {
      this.pendingRegistrations.delete(cleanEmail);
      throw new Error('Verification code has expired. Please request a new registration code.');
    }

    pending.attempts += 1;
    if (pending.attempts > 5) {
      this.pendingRegistrations.delete(cleanEmail);
      throw new Error('Too many incorrect code attempts. Please start registration again for security.');
    }

    if (pending.code !== inputCode.trim()) {
      throw new Error(`Invalid verification code. ${5 - pending.attempts} attempts remaining.`);
    }

    // Double check user doesn't already exist
    const existing = this.users.find((u) => u.email.toLowerCase() === cleanEmail);
    if (existing) {
      this.pendingRegistrations.delete(cleanEmail);
      throw new Error('Account already created. Please sign in.');
    }

    const newUser: StoredUser = {
      id: 'optiv-usr-' + crypto.randomBytes(8).toString('hex'),
      email: cleanEmail,
      displayName: pending.displayName,
      passwordHash: pending.passwordHash,
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
      role: cleanEmail.endsWith('@optiv.com') ? 'Optiv SOC Analyst' : 'SOC Analyst'
    };

    this.users.push(newUser);
    this.saveUsers();
    this.pendingRegistrations.delete(cleanEmail);

    return {
      id: newUser.id,
      email: newUser.email,
      displayName: newUser.displayName
    };
  }

  /**
   * Step 1 of Password Reset: Request 6-digit reset code
   */
  public async initiatePasswordReset(
    email: string
  ): Promise<{ message: string; email: string; mailStatus: SendMailResult }> {
    const cleanEmail = email.trim().toLowerCase();
    if (!isAllowedEmail(cleanEmail)) {
      throw new Error('Access Denied: Only @optiv.com or @gmail.com emails are accepted.');
    }

    const user = this.users.find((u) => u.email.toLowerCase() === cleanEmail);
    if (!user) {
      throw new Error('No registered analyst account found for this email. Please check your address or register.');
    }

    const code = this.generate6DigitCode();
    const now = Date.now();
    const expiresAt = now + 10 * 60 * 1000; // 10 minutes

    this.pendingResets.set(cleanEmail, {
      email: cleanEmail,
      code,
      createdAt: now,
      expiresAt,
      attempts: 0
    });

    const mailStatus = await mailer.sendVerificationCode(cleanEmail, code, 'password_reset');

    return {
      message: mailStatus.sentViaSmtp
        ? `A 6-digit password reset code has been sent to ${cleanEmail}.`
        : `A password reset code has been generated for ${cleanEmail}.`,
      email: cleanEmail,
      mailStatus
    };
  }

  /**
   * Step 2 of Password Reset: Confirm code and set new password
   */
  public confirmPasswordReset(
    email: string,
    inputCode: string,
    newPassword: string
  ): { success: boolean; message: string } {
    const cleanEmail = email.trim().toLowerCase();
    const pending = this.pendingResets.get(cleanEmail);

    if (!pending) {
      throw new Error('No pending password reset request found for this email, or the request has expired.');
    }

    if (Date.now() > pending.expiresAt) {
      this.pendingResets.delete(cleanEmail);
      throw new Error('Password reset code has expired. Please request a new code.');
    }

    pending.attempts += 1;
    if (pending.attempts > 5) {
      this.pendingResets.delete(cleanEmail);
      throw new Error('Too many invalid attempts. Please request a new password reset code.');
    }

    if (pending.code !== inputCode.trim()) {
      throw new Error(`Invalid reset code. ${5 - pending.attempts} attempts remaining.`);
    }

    if (!newPassword || newPassword.length < 6) {
      throw new Error('Security requirement: New password must be at least 6 characters.');
    }

    const user = this.users.find((u) => u.email.toLowerCase() === cleanEmail);
    if (!user) {
      throw new Error('User not found.');
    }

    user.passwordHash = this.hashPassword(newPassword);
    user.lastLoginAt = new Date().toISOString();
    this.saveUsers();
    this.pendingResets.delete(cleanEmail);

    return {
      success: true,
      message: 'Password reset successful. You can now log in with your new security password.'
    };
  }

  /**
   * Standard Email/Password login
   */
  public login(email: string, pass: string): { id: string; email: string; displayName: string } {
    const cleanEmail = email.trim().toLowerCase();
    if (!isAllowedEmail(cleanEmail)) {
      throw new Error('Access Denied: Only @optiv.com or @gmail.com emails are authorized.');
    }

    const user = this.users.find((u) => u.email.toLowerCase() === cleanEmail);
    if (!user) {
      throw new Error('No account found for this email. Please register first or check your address.');
    }

    const match = this.verifyPassword(pass, user.passwordHash);
    if (!match) {
      throw new Error('Invalid security password. Please re-enter or use "Forgot Password".');
    }

    user.lastLoginAt = new Date().toISOString();
    this.saveUsers();

    return {
      id: user.id,
      email: user.email,
      displayName: user.displayName
    };
  }
}

export const userAuth = new UserAuthManager();
