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

// Helper for user validation
export function isAllowedEmail(email?: string | null): boolean {
  return Boolean(email && email.trim().length > 0);
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
