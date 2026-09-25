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

// Validation helper: strictly accept optiv.com (and developer admin account)
export function isOptivEmail(email?: string | null): boolean {
  if (!email) return false;
  const clean = email.trim().toLowerCase();
  return clean.endsWith('@optiv.com') || clean === 'jai.learn.official@gmail.com';
}

interface AuthContextType {
  user: User | null;
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

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [isUnauthorizedDomain, setIsUnauthorizedDomain] = useState<boolean>(false);
  const [currentHost, setCurrentHost] = useState<string>('');

  useEffect(() => {
    if (typeof window !== 'undefined') {
      setCurrentHost(window.location.hostname);
    }

    // Clear any previous legacy session storage
    try {
      sessionStorage.removeItem('soc_analyst_session');
    } catch {}

    // Test Firestore connection on boot
    testConnection().catch((err) => {
      console.warn('Initial Firestore connection probe:', err);
    });

    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      if (currentUser) {
        // Enforce strict @optiv.com restriction
        if (!isOptivEmail(currentUser.email)) {
          await fbSignOut(auth);
          setUser(null);
          setAuthError(
            `Access Denied: Only @optiv.com corporate email addresses are authorized. Attempted logon: ${currentUser.email || 'Unknown'}`
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
        setUser(null);
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
        if (!isOptivEmail(result.user.email)) {
          await fbSignOut(auth);
          setUser(null);
          const rejectedMsg = `Access Denied: Only @optiv.com accounts are authorized. Logged-in Google account: ${result.user.email}`;
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
          `Domain Unauthorized: "${window.location.hostname}" is not yet in the Firebase Authorized Domains list. Add it to Firebase Console settings.`
        );
      } else if (errMsg.includes('popup-closed-by-user')) {
        setAuthError('Authentication window closed before completion.');
      } else if (!errMsg.includes('Access Denied: Only @optiv.com')) {
        setAuthError(errMsg);
      }
      throw err;
    }
  };

  const signInWithEmail = async (email: string, pass: string) => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);

    const cleanEmail = email.trim();
    if (!isOptivEmail(cleanEmail)) {
      const err = 'Access Denied: Only @optiv.com corporate email addresses are permitted.';
      setAuthError(err);
      throw new Error(err);
    }

    try {
      const result = await signInWithEmailAndPassword(auth, cleanEmail, pass);
      if (result.user) {
        if (!isOptivEmail(result.user.email)) {
          await fbSignOut(auth);
          setUser(null);
          const err = `Access Denied: Only @optiv.com accounts are authorized.`;
          setAuthError(err);
          throw new Error(err);
        }
        await syncUserProfile(result.user);
      }
    } catch (err: unknown) {
      console.error('Email sign-in error:', err);
      const errMsg = err instanceof Error ? err.message : 'Authentication failed.';

      if (errMsg.includes('auth/operation-not-allowed')) {
        setAuthError(
          'Email/Password sign-in is not yet toggled ON in your Firebase project. Please enable Email/Password provider in the Firebase Console (Authentication > Sign-in method).'
        );
      } else if (errMsg.includes('auth/invalid-credential') || errMsg.includes('auth/user-not-found') || errMsg.includes('auth/wrong-password')) {
        setAuthError('Invalid credentials. If this is your first time logging in with this @optiv.com email, please click "Register New Optiv Analyst".');
      } else {
        setAuthError(errMsg);
      }
      throw err;
    }
  };

  const registerWithEmail = async (email: string, pass: string, name: string) => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);

    const cleanEmail = email.trim();
    if (!isOptivEmail(cleanEmail)) {
      const err = 'Access Denied: Only @optiv.com corporate email addresses can be registered.';
      setAuthError(err);
      throw new Error(err);
    }

    if (!pass || pass.length < 6) {
      const err = 'Security requirement: Password must be at least 6 characters.';
      setAuthError(err);
      throw new Error(err);
    }

    try {
      const result = await createUserWithEmailAndPassword(auth, cleanEmail, pass);
      if (result.user) {
        if (name.trim()) {
          await updateProfile(result.user, { displayName: name.trim() });
        }
        await syncUserProfile(result.user);
      }
    } catch (err: unknown) {
      console.error('Email registration error:', err);
      const errMsg = err instanceof Error ? err.message : 'Registration failed.';

      if (errMsg.includes('auth/operation-not-allowed')) {
        setAuthError(
          'Email/Password provider is not yet enabled in Firebase Console. Go to Firebase Console > Authentication > Sign-in method and enable Email/Password.'
        );
      } else if (errMsg.includes('auth/email-already-in-use')) {
        setAuthError('An account with this @optiv.com email already exists. Please switch to "Sign In".');
      } else {
        setAuthError(errMsg);
      }
      throw err;
    }
  };

  const signOut = async () => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);
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
