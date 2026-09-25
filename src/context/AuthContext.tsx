import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  auth,
  googleProvider,
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  updateProfile,
  fbSignOut,
  onAuthStateChanged,
  User,
  testConnection,
  syncUserProfile
} from '../lib/firebase.js';

export interface AuthUser {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL?: string | null;
}

export interface SmtpStatus {
  configured: boolean;
  host: string | null;
  user: string | null;
}

export interface VerificationResult {
  message: string;
  email: string;
  previewCode?: string;
  sentViaSmtp: boolean;
}

// Validation helper: strictly accept @optiv.com and @gmail.com
export function isAllowedEmail(email?: string | null): boolean {
  if (!email) return false;
  const clean = email.trim().toLowerCase();
  return clean.endsWith('@optiv.com') || clean.endsWith('@gmail.com');
}

export const isOptivEmail = isAllowedEmail;

interface AuthContextType {
  user: User | AuthUser | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signInWithEmail: (email: string, pass: string) => Promise<void>;
  initiateRegistration: (email: string, pass: string, name: string) => Promise<VerificationResult>;
  confirmRegistration: (email: string, code: string) => Promise<void>;
  initiatePasswordReset: (email: string) => Promise<VerificationResult>;
  confirmPasswordReset: (email: string, code: string, newPass: string) => Promise<string>;
  signOut: () => Promise<void>;
  authError: string | null;
  isUnauthorizedDomain: boolean;
  currentHost: string;
  smtpStatus: SmtpStatus;
  clearAuthError: () => void;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  signInWithGoogle: async () => {},
  signInWithEmail: async () => {},
  initiateRegistration: async () => ({ message: '', email: '', sentViaSmtp: false }),
  confirmRegistration: async () => {},
  initiatePasswordReset: async () => ({ message: '', email: '', sentViaSmtp: false }),
  confirmPasswordReset: async () => '',
  signOut: async () => {},
  authError: null,
  isUnauthorizedDomain: false,
  currentHost: '',
  smtpStatus: { configured: false, host: null, user: null },
  clearAuthError: () => {}
});

const STORAGE_KEY = 'threatlense_auth_analyst';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | AuthUser | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [isUnauthorizedDomain, setIsUnauthorizedDomain] = useState<boolean>(false);
  const [currentHost, setCurrentHost] = useState<string>('');
  const [smtpStatus, setSmtpStatus] = useState<SmtpStatus>({
    configured: false,
    host: null,
    user: null
  });

  useEffect(() => {
    if (typeof window !== 'undefined') {
      setCurrentHost(window.location.hostname);
    }

    // Check SMTP status
    fetch('/api/auth/smtp-status')
      .then((res) => res.json())
      .then((data) => {
        setSmtpStatus({
          configured: Boolean(data.configured),
          host: data.host,
          user: data.user
        });
      })
      .catch(() => {});

    // 1. Check for stored analyst session
    let restoredLocalUser: AuthUser | null = null;
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as AuthUser;
        if (parsed?.email && isAllowedEmail(parsed.email)) {
          restoredLocalUser = parsed;
          setUser(parsed);
        }
      }
    } catch {}

    // Test Firestore connection on boot
    testConnection().catch((err) => {
      console.warn('Initial Firestore connection probe:', err);
    });

    // 2. Listen to Firebase Google Auth state
    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      if (currentUser) {
        if (!isAllowedEmail(currentUser.email)) {
          await fbSignOut(auth);
          setUser(null);
          setAuthError(
            `Access Denied: Only @optiv.com or @gmail.com accounts are authorized. Attempted logon: ${currentUser.email || 'Unknown'}`
          );
          setLoading(false);
          return;
        }

        setUser(currentUser);
        try {
          await syncUserProfile(currentUser);
        } catch (e) {
          console.error('Failed to sync user profile:', e);
        }
      } else {
        if (!restoredLocalUser) {
          setUser(null);
        }
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signInWithGoogle = async () => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);
    try {
      const result = await signInWithPopup(auth, googleProvider);
      if (result.user) {
        if (!isAllowedEmail(result.user.email)) {
          await fbSignOut(auth);
          setUser(null);
          const rejectedMsg = `Access Denied: Only @optiv.com or @gmail.com accounts are authorized. Logged-in Google account: ${result.user.email}`;
          setAuthError(rejectedMsg);
          throw new Error(rejectedMsg);
        }
        await syncUserProfile(result.user);
      }
    } catch (err: unknown) {
      console.error('Google Authentication error:', err);
      const errMsg = err instanceof Error ? err.message : 'Google sign-in failed.';

      if (errMsg.includes('auth/unauthorized-domain')) {
        setIsUnauthorizedDomain(true);
        setAuthError(
          `Domain Unauthorized: "${window.location.hostname}" is not yet in the Firebase Authorized Domains list. Add it to Firebase Console or use Email Sign-In.`
        );
      } else if (errMsg.includes('popup-closed-by-user')) {
        setAuthError('Authentication window closed before completion.');
      } else if (!errMsg.includes('Access Denied: Only')) {
        setAuthError(errMsg);
      }
      throw err;
    }
  };

  const signInWithEmail = async (email: string, pass: string) => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);

    const cleanEmail = email.trim().toLowerCase();
    if (!isAllowedEmail(cleanEmail)) {
      const err = 'Access Denied: Only @optiv.com or @gmail.com email addresses are permitted.';
      setAuthError(err);
      throw new Error(err);
    }

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: cleanEmail, password: pass })
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Authentication failed. Please check your credentials.');
      }

      const authenticatedAnalyst: AuthUser = {
        uid: data.user.id,
        email: data.user.email,
        displayName: data.user.displayName,
        photoURL: null
      };

      setUser(authenticatedAnalyst);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(authenticatedAnalyst));
      } catch {}

      // Optional background sync
      signInWithEmailAndPassword(auth, cleanEmail, pass).catch(() => {});
    } catch (err: unknown) {
      console.error('Email sign-in error:', err);
      const errMsg = err instanceof Error ? err.message : 'Authentication failed.';
      setAuthError(errMsg);
      throw err;
    }
  };

  const initiateRegistration = async (email: string, pass: string, name: string): Promise<VerificationResult> => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);

    const cleanEmail = email.trim().toLowerCase();
    if (!isAllowedEmail(cleanEmail)) {
      const err = 'Access Denied: Only @optiv.com or @gmail.com email addresses can be registered.';
      setAuthError(err);
      throw new Error(err);
    }

    if (!pass || pass.length < 6) {
      const err = 'Security requirement: Password must be at least 6 characters.';
      setAuthError(err);
      throw new Error(err);
    }

    try {
      const response = await fetch('/api/auth/register/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: cleanEmail,
          password: pass,
          displayName: name.trim() || cleanEmail.split('@')[0]
        })
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Registration initiation failed.');
      }

      return {
        message: data.message,
        email: data.email,
        previewCode: data.mailStatus?.previewCode,
        sentViaSmtp: Boolean(data.mailStatus?.sentViaSmtp)
      };
    } catch (err: unknown) {
      console.error('Initiate registration error:', err);
      const errMsg = err instanceof Error ? err.message : 'Failed to send verification code.';
      setAuthError(errMsg);
      throw err;
    }
  };

  const confirmRegistration = async (email: string, code: string): Promise<void> => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);

    const cleanEmail = email.trim().toLowerCase();
    const cleanCode = code.trim();

    if (!cleanCode || cleanCode.length < 6) {
      const err = 'Please enter the complete 6-digit verification code.';
      setAuthError(err);
      throw new Error(err);
    }

    try {
      const response = await fetch('/api/auth/register/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: cleanEmail, code: cleanCode })
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Verification failed. Please check the code.');
      }

      const authenticatedAnalyst: AuthUser = {
        uid: data.user.id,
        email: data.user.email,
        displayName: data.user.displayName,
        photoURL: null
      };

      setUser(authenticatedAnalyst);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(authenticatedAnalyst));
      } catch {}
    } catch (err: unknown) {
      console.error('Confirm registration error:', err);
      const errMsg = err instanceof Error ? err.message : 'Registration verification failed.';
      setAuthError(errMsg);
      throw err;
    }
  };

  const initiatePasswordReset = async (email: string): Promise<VerificationResult> => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);

    const cleanEmail = email.trim().toLowerCase();
    if (!isAllowedEmail(cleanEmail)) {
      const err = 'Access Denied: Only @optiv.com or @gmail.com email addresses are authorized.';
      setAuthError(err);
      throw new Error(err);
    }

    try {
      const response = await fetch('/api/auth/reset/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: cleanEmail })
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Password reset request failed.');
      }

      return {
        message: data.message,
        email: data.email,
        previewCode: data.mailStatus?.previewCode,
        sentViaSmtp: Boolean(data.mailStatus?.sentViaSmtp)
      };
    } catch (err: unknown) {
      console.error('Initiate password reset error:', err);
      const errMsg = err instanceof Error ? err.message : 'Failed to request password reset code.';
      setAuthError(errMsg);
      throw err;
    }
  };

  const confirmPasswordReset = async (email: string, code: string, newPass: string): Promise<string> => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);

    const cleanEmail = email.trim().toLowerCase();
    const cleanCode = code.trim();

    if (!cleanCode || cleanCode.length < 6) {
      const err = 'Please enter the complete 6-digit verification code.';
      setAuthError(err);
      throw new Error(err);
    }

    if (!newPass || newPass.length < 6) {
      const err = 'Security requirement: New password must be at least 6 characters.';
      setAuthError(err);
      throw new Error(err);
    }

    try {
      const response = await fetch('/api/auth/reset/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: cleanEmail, code: cleanCode, newPassword: newPass })
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Password reset failed.');
      }

      return data.message || 'Password reset successful.';
    } catch (err: unknown) {
      console.error('Confirm password reset error:', err);
      const errMsg = err instanceof Error ? err.message : 'Password reset failed.';
      setAuthError(errMsg);
      throw err;
    }
  };

  const signOut = async () => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {}
    try {
      await fbSignOut(auth);
    } catch (err: unknown) {
      console.error('Sign out error:', err);
    }
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        signInWithGoogle,
        signInWithEmail,
        initiateRegistration,
        confirmRegistration,
        initiatePasswordReset,
        confirmPasswordReset,
        signOut,
        authError,
        isUnauthorizedDomain,
        currentHost,
        smtpStatus,
        clearAuthError: () => {
          setAuthError(null);
          setIsUnauthorizedDomain(false);
        }
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
