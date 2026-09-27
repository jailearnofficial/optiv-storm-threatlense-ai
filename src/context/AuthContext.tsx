import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  auth,
  googleProvider,
  signInWithPopup,
  fbSignOut,
  onAuthStateChanged,
  sendSignInLinkToEmail,
  isSignInWithEmailLink,
  signInWithEmailLink,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  User,
  testConnection,
  syncUserProfile
} from '../lib/firebase.js';

// Helper for user validation: Allow only @optiv.com corporate domain and verified @gmail.com accounts
export function isAllowedEmail(email?: string | null): boolean {
  if (!email) return false;
  const clean = email.trim().toLowerCase();
  return clean.endsWith('@optiv.com') || clean.endsWith('@gmail.com');
}

export const isOptivEmail = isAllowedEmail;

const EMAIL_LINK_KEY = 'threatlense_email_for_signin';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  sendEmailSignInLink: (email: string) => Promise<void>;
  signInWithEmail: (email: string, password?: string) => Promise<void>;
  signOut: () => Promise<void>;
  authError: string | null;
  emailLinkSentTo: string | null;
  isUnauthorizedDomain: boolean;
  currentHost: string;
  clearAuthError: () => void;
  clearEmailLinkSent: () => void;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  signInWithGoogle: async () => {},
  sendEmailSignInLink: async () => {},
  signInWithEmail: async () => {},
  signOut: async () => {},
  authError: null,
  emailLinkSentTo: null,
  isUnauthorizedDomain: false,
  currentHost: '',
  clearAuthError: () => {},
  clearEmailLinkSent: () => {}
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [emailLinkSentTo, setEmailLinkSentTo] = useState<string | null>(null);
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

    // Check if the current URL is an incoming Firebase Email Verification Link
    if (typeof window !== 'undefined' && isSignInWithEmailLink(auth, window.location.href)) {
      let email = window.localStorage.getItem(EMAIL_LINK_KEY);
      if (!email) {
        email = window.prompt('Please confirm your @optiv.com or @gmail.com email for verification:');
      }
      if (email && isAllowedEmail(email)) {
        signInWithEmailLink(auth, email, window.location.href)
          .then(async (result) => {
            window.localStorage.removeItem(EMAIL_LINK_KEY);
            if (window.history && window.history.replaceState) {
              window.history.replaceState({}, document.title, window.location.pathname);
            }
            if (result.user) {
              await syncUserProfile(result.user);
            }
          })
          .catch((err) => {
            console.error('Email Link Sign-In failed:', err);
            setAuthError(err instanceof Error ? err.message : 'Email verification link expired or invalid.');
          });
      } else if (email && !isAllowedEmail(email)) {
        setAuthError(`Email ${email} is not authorized. Must be @optiv.com or @gmail.com.`);
      }
    }

    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      if (currentUser) {
        if (!isAllowedEmail(currentUser.email)) {
          await fbSignOut(auth);
          setUser(null);
          setAuthError(
            `Access Denied: Account "${currentUser.email}" is not authorized. Only official @optiv.com and verified @gmail.com accounts are permitted.`
          );
        } else {
          setUser(currentUser);
          try {
            await syncUserProfile(currentUser);
          } catch (e) {
            console.error('Failed to sync user profile:', e);
          }
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
          setAuthError(
            `Access Denied: "${result.user.email}" is not authorized. Only @optiv.com and verified @gmail.com accounts are permitted.`
          );
          return;
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
      } else {
        setAuthError(errMsg);
      }
      throw err;
    }
  };

  const sendEmailSignInLink = async (email: string) => {
    setAuthError(null);
    setEmailLinkSentTo(null);

    const cleanEmail = email.trim().toLowerCase();
    if (!isAllowedEmail(cleanEmail)) {
      setAuthError(
        `Restricted Access: "${cleanEmail}" is unauthorized. Only @optiv.com and verified @gmail.com accounts are permitted.`
      );
      return;
    }

    const actionCodeSettings = {
      url: window.location.href,
      handleCodeInApp: true
    };

    try {
      await sendSignInLinkToEmail(auth, cleanEmail, actionCodeSettings);
      window.localStorage.setItem(EMAIL_LINK_KEY, cleanEmail);
      setEmailLinkSentTo(cleanEmail);
    } catch (err: unknown) {
      console.warn('Firebase sendSignInLinkToEmail note:', err);
      const rawMsg = err instanceof Error ? err.message : 'Failed to send verification link.';
      if (rawMsg.includes('auth/unauthorized-domain')) {
        setIsUnauthorizedDomain(true);
      } else if (rawMsg.includes('auth/operation-not-allowed')) {
        setAuthError(
          'Email Link authentication is currently awaiting provider activation in Firebase Console. You can authenticate directly using "Sign in with Google" or with your password.'
        );
      } else {
        setAuthError(rawMsg);
      }
    }
  };

  const signInWithEmail = async (email: string, password?: string) => {
    setAuthError(null);
    const cleanEmail = email.trim().toLowerCase();
    if (!isAllowedEmail(cleanEmail)) {
      setAuthError(
        `Restricted Access: "${cleanEmail}" is not authorized. Only @optiv.com and @gmail.com accounts are permitted.`
      );
      return;
    }

    if (!password) {
      // If no password provided, trigger email verification link dispatch
      await sendEmailSignInLink(cleanEmail);
      return;
    }

    try {
      const res = await signInWithEmailAndPassword(auth, cleanEmail, password);
      if (res.user) {
        if (!isAllowedEmail(res.user.email)) {
          await fbSignOut(auth);
          setUser(null);
          setAuthError(`Access Denied: "${res.user.email}" is not authorized.`);
          return;
        }
        await syncUserProfile(res.user);
      }
    } catch (err: unknown) {
      console.warn('Firebase signInWithEmailAndPassword error:', err);
      const msg = err instanceof Error ? err.message : 'Authentication failed.';
      if (msg.includes('auth/user-not-found') || msg.includes('auth/invalid-credential')) {
        // If user not found, try creating the authorized account
        try {
          const createRes = await createUserWithEmailAndPassword(auth, cleanEmail, password);
          if (createRes.user) {
            await syncUserProfile(createRes.user);
            return;
          }
        } catch (createErr: unknown) {
          const cMsg = createErr instanceof Error ? createErr.message : 'Failed to create account.';
          setAuthError(cMsg);
          return;
        }
      }
      setAuthError(msg);
    }
  };

  const signOut = async () => {
    setAuthError(null);
    setIsUnauthorizedDomain(false);
    setEmailLinkSentTo(null);
    try {
      localStorage.removeItem('threatlense_active_lookup_id');
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
        sendEmailSignInLink,
        signInWithEmail,
        signOut,
        authError,
        emailLinkSentTo,
        isUnauthorizedDomain,
        currentHost,
        clearAuthError: () => {
          setAuthError(null);
          setIsUnauthorizedDomain(false);
        },
        clearEmailLinkSent: () => {
          setEmailLinkSentTo(null);
        }
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
