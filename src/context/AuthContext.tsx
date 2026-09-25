import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  auth,
  googleProvider,
  signInWithPopup,
  fbSignOut,
  onAuthStateChanged,
  User,
  testConnection,
  syncUserProfile
} from '../lib/firebase.js';

// Validation helper: strictly accept @optiv.com and @gmail.com
export function isAllowedEmail(email?: string | null): boolean {
  if (!email) return false;
  const clean = email.trim().toLowerCase();
  return clean.endsWith('@optiv.com') || clean.endsWith('@gmail.com');
}

export const isOptivEmail = isAllowedEmail;

interface AuthContextType {
  user: User | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
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

    // Verify Firestore connection on boot
    testConnection().catch((err) => {
      console.warn('Initial Firestore connection probe:', err);
    });

    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      if (currentUser) {
        // Enforce @optiv.com or @gmail.com restriction
        if (!isAllowedEmail(currentUser.email)) {
          await fbSignOut(auth);
          setUser(null);
          setAuthError(
            `Access Denied: Only @optiv.com or @gmail.com email addresses are authorized. Attempted logon: ${currentUser.email || 'Unknown'}`
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
          `Domain Unauthorized: "${window.location.hostname}" is not yet in the Firebase Authorized Domains list. Please add this domain in Firebase Console to enable Google Sign-In.`
        );
      } else if (errMsg.includes('popup-closed-by-user')) {
        setAuthError('Authentication window closed before completion.');
      } else if (!errMsg.includes('Access Denied: Only')) {
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
