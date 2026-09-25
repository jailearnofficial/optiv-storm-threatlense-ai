import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export interface StoredUser {
  id: string;
  email: string;
  displayName: string;
  passwordHash: string;
  createdAt: string;
  lastLoginAt: string;
  role: string;
}

export function isAllowedEmail(email?: string | null): boolean {
  if (!email) return false;
  const clean = email.trim().toLowerCase();
  return clean.endsWith('@optiv.com') || clean.endsWith('@gmail.com');
}

class UserAuthManager {
  private usersPath: string;
  private users: StoredUser[] = [];

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

  public register(email: string, pass: string, name?: string): { id: string; email: string; displayName: string } {
    const cleanEmail = email.trim().toLowerCase();
    if (!isAllowedEmail(cleanEmail)) {
      throw new Error('Access Denied: Only @optiv.com or @gmail.com emails are accepted.');
    }

    if (!pass || pass.length < 6) {
      throw new Error('Security requirement: Password must be at least 6 characters.');
    }

    const existing = this.users.find((u) => u.email.toLowerCase() === cleanEmail);
    if (existing) {
      throw new Error('An account with this email already exists. Please switch to Sign In.');
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(pass, salt, 64).toString('hex');
    const passwordHash = `${salt}:${hash}`;

    const displayName =
      name && name.trim().length > 0
        ? name.trim().substring(0, 64)
        : cleanEmail.split('@')[0];

    const newUser: StoredUser = {
      id: 'optiv-usr-' + crypto.randomBytes(8).toString('hex'),
      email: cleanEmail,
      displayName,
      passwordHash,
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
      role: cleanEmail.endsWith('@optiv.com') ? 'Optiv SOC Analyst' : 'SOC Analyst'
    };

    this.users.push(newUser);
    this.saveUsers();

    return {
      id: newUser.id,
      email: newUser.email,
      displayName: newUser.displayName
    };
  }

  public login(email: string, pass: string): { id: string; email: string; displayName: string } {
    const cleanEmail = email.trim().toLowerCase();
    if (!isAllowedEmail(cleanEmail)) {
      throw new Error('Access Denied: Only @optiv.com or @gmail.com emails are authorized.');
    }

    const user = this.users.find((u) => u.email.toLowerCase() === cleanEmail);
    if (!user) {
      throw new Error('User not found. If this is your first time, please click "Register Analyst Account".');
    }

    const [salt, storedHash] = user.passwordHash.split(':');
    if (!salt || !storedHash) {
      throw new Error('Credential integrity error.');
    }

    const calcHash = crypto.scryptSync(pass, salt, 64).toString('hex');
    const match = crypto.timingSafeEqual(Buffer.from(storedHash, 'hex'), Buffer.from(calcHash, 'hex'));

    if (!match) {
      throw new Error('Invalid password. Please check your credentials.');
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
