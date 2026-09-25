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

export interface AppUser {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
  isDemo?: boolean;
}

interface AuthContextType {
  user: User | AppUser | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signInAsEmergencyAnalyst: (customName?: string) => void;
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
  signInAsEmergencyAnalyst: () => {},
  signOut: async () => {},
  authError: null,
  isUnauthorizedDomain: false,
  currentHost: '',
  clearAuthError: () => {}
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | AppUser | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [isUnauthorizedDomain, setIsUnauthorizedDomain] = useState<boolean>(false);
  const [currentHost, setCurrentHost] = useState<string>('');

  useEffect(() => {
    if (typeof window !== 'undefined') {
      setCurrentHost(window.location.hostname);
    }

    // Check if there was a saved emergency session in sessionStorage
    try {
      const savedSession = sessionStorage.getItem('soc_analyst_session');
      if (savedSession) {
        const parsed = JSON.parse(savedSession);
        if (parsed?.uid) {
          setUser(parsed);
          setLoading(false);
          return;
        }
      }
    } catch {}

    // Test Firestore connection on boot
    testConnection().catch((err) => {
      console.warn('Initial Firestore connection probe:', err);
    });

    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      if (currentUser) {
        try {
          await syncUserProfile(currentUser);
        } catch (e) {
          console.error('Failed to sync user profile:', e);
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
        try {
          sessionStorage.removeItem('soc_analyst_session');
        } catch {}
        await syncUserProfile(result.user);
      }
    } catch (err: unknown) {
      console.error('Authentication error:', err);
      const errMsg = err instanceof Error ? err.message : 'Sign-in failed. Please try again.';
      
      if (errMsg.includes('auth/unauthorized-domain')) {
        setIsUnauthorizedDomain(true);
        setAuthError(
          `Domain Unauthorized: "${window.location.hostname}" is not yet in the Firebase Authorized Domains list. Add it to Firebase Console or use Quick Analyst Access.`
        );
      } else if (errMsg.includes('popup-closed-by-user')) {
        setAuthError('Authentication prompt closed. Please complete Google sign-in to access the SOC console.');
      } else {
        setAuthError(errMsg);
      }
      throw err;
    }
  };

  const signInAsEmergencyAnalyst = (customName?: string) => {
    const demoAnalyst: AppUser = {
      uid: 'soc-analyst-' + Math.random().toString(36).substring(2, 9),
      email: 'analyst.tier2@optiv-storm.internal',
      displayName: customName || 'Tier-2 SOC Analyst',
      photoURL: '',
      isDemo: true
    };
    setUser(demoAnalyst);
    setAuthError(null);
    setIsUnauthorizedDomain(false);
    try {
      sessionStorage.setItem('soc_analyst_session', JSON.stringify(demoAnalyst));
    } catch {}
  };

  const signOut = async () => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);
    try {
      sessionStorage.removeItem('soc_analyst_session');
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
        signInAsEmergencyAnalyst,
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

