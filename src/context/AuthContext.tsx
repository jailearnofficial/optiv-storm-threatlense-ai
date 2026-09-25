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
  registerWithEmail: (email: string, pass: string, name: string) => Promise<void>;
  signOut: () => Promise<void>;
  authError: string | null;
  isUnauthorizedDomain: boolean;
  currentHost: string;
  clearAuthError: () => void;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  signInWithGoogle: async () => {},
  signInWithEmail: async () => {},
  registerWithEmail: async () => {},
  signOut: async () => {},
  authError: null,
  isUnauthorizedDomain: false,
  currentHost: '',
  clearAuthError: () => {}
});

const STORAGE_KEY = 'threatlense_auth_analyst';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | AuthUser | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [isUnauthorizedDomain, setIsUnauthorizedDomain] = useState<boolean>(false);
  const [currentHost, setCurrentHost] = useState<string>('');

  useEffect(() => {
    if (typeof window !== 'undefined') {
      setCurrentHost(window.location.hostname);
    }

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
        // If no Firebase user, retain the stored local user session if present
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
      // Authenticate against our backend auth provider
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

      // Background optional Firebase Auth attempt (if enabled)
      signInWithEmailAndPassword(auth, cleanEmail, pass).catch(() => {});
    } catch (err: unknown) {
      console.error('Email sign-in error:', err);
      const errMsg = err instanceof Error ? err.message : 'Authentication failed.';
      setAuthError(errMsg);
      throw err;
    }
  };

  const registerWithEmail = async (email: string, pass: string, name: string) => {
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
      // Register with backend auth provider
      const response = await fetch('/api/auth/register', {
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
        throw new Error(data.error || 'Registration failed.');
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

      // Background optional Firebase Auth registration (if enabled)
      createUserWithEmailAndPassword(auth, cleanEmail, pass)
        .then(async (cred) => {
          if (name.trim()) {
            await updateProfile(cred.user, { displayName: name.trim() });
          }
        })
        .catch(() => {});
    } catch (err: unknown) {
      console.error('Email registration error:', err);
      const errMsg = err instanceof Error ? err.message : 'Registration failed.';
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
        registerWithEmail,
        signOut,
        authError,
        isUnauthorizedDomain,
        currentHost,
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
