import { initializeApp, getApps, getApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut as fbSignOut,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  updateProfile,
  User
} from 'firebase/auth';
import { getFirestore, doc, getDocFromServer, setDoc, getDoc } from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';

// Initialize Firebase App
const app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);

// CRITICAL: Initialize Firestore with configured database ID
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);

// Initialize Firebase Auth
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: 'select_account' });

// Error handling as mandated by Firebase skill
export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write'
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo: auth.currentUser?.providerData?.map((p) => ({
        providerId: p.providerId,
        email: p.email
      })) || []
    },
    operationType,
    path
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

// Test connection on boot constraint
export async function testConnection(): Promise<boolean> {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
    return true;
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
    // Expected PERMISSION_DENIED or not-found for test probe is fine for connection validation
    return false;
  }
}

// Sync user profile to Firestore
export async function syncUserProfile(user: User): Promise<void> {
  const userRef = doc(db, 'users', user.uid);
  try {
    const existing = await getDoc(userRef);
    const now = new Date().toISOString();
    if (!existing.exists()) {
      await setDoc(userRef, {
        uid: user.uid,
        email: user.email || 'unknown@analyst.soc',
        displayName: user.displayName || user.email?.split('@')[0] || 'SOC Analyst',
        photoURL: user.photoURL || '',
        role: 'Tier-1/2 SOC Analyst',
        createdAt: now,
        lastLoginAt: now
      });
    } else {
      await setDoc(userRef, {
        ...existing.data(),
        lastLoginAt: now,
        displayName: user.displayName || existing.data()?.displayName || 'SOC Analyst',
        photoURL: user.photoURL || existing.data()?.photoURL || ''
      }, { merge: true });
    }
  } catch (err) {
    // Log error using required handler
    try {
      handleFirestoreError(err, OperationType.WRITE, `users/${user.uid}`);
    } catch {
      // Handled and logged
    }
  }
}

export {
  signInWithPopup,
  fbSignOut,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  updateProfile
};
export type { User };
