import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Sparkles,
  ArrowRight,
  Radio,
  Cpu,
  AlertTriangle,
  Fingerprint,
  Copy,
  Check,
  ExternalLink,
  Mail,
  KeyRound,
  User,
  Building2,
  RefreshCw,
  ArrowLeft,
  CheckCircle2,
  Info
} from 'lucide-react';
import { useAuth, isOptivEmail, VerificationResult } from '../context/AuthContext.js';

type EmailView =
  | 'sign_in'
  | 'register_initiate'
  | 'register_verify'
  | 'forgot_request'
  | 'forgot_verify'
  | 'reset_success';

export const LoginGate: React.FC = () => {
  const {
    signInWithGoogle,
    signInWithEmail,
    initiateRegistration,
    confirmRegistration,
    initiatePasswordReset,
    confirmPasswordReset,
    authError,
    isUnauthorizedDomain,
    currentHost,
    smtpStatus,
    clearAuthError
  } = useAuth();

  // Top tabs: 'google' | 'email'
  const [authMethod, setAuthMethod] = useState<'google' | 'email'>('google');

  // Email sub-view
  const [emailView, setEmailView] = useState<EmailView>('sign_in');
  const [submitting, setSubmitting] = useState(false);
  const [copied, setCopied] = useState(false);

  // Form states
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [analystName, setAnalystName] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [localMessage, setLocalMessage] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const [activePreviewCode, setActivePreviewCode] = useState<string | null>(null);

  const currentDomain =
    currentHost || (typeof window !== 'undefined' ? window.location.hostname : '');
  const firebaseSettingsUrl =
    'https://console.firebase.google.com/project/gen-lang-client-0906610882/authentication/settings';

  const handleCopyDomain = () => {
    if (navigator?.clipboard && currentDomain) {
      navigator.clipboard.writeText(currentDomain);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  const resetAllFields = () => {
    clearAuthError();
    setLocalError(null);
    setLocalMessage(null);
    setActivePreviewCode(null);
  };

  const handleGoogleLogin = async () => {
    resetAllFields();
    setSubmitting(true);
    try {
      await signInWithGoogle();
    } catch {
      // Handled in context
    } finally {
      setSubmitting(false);
    }
  };

  // 1. Sign In
  const handleEmailSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    resetAllFields();

    const cleanEmail = email.trim();
    if (!cleanEmail) {
      setLocalError('Please enter your email address.');
      return;
    }
    if (!isOptivEmail(cleanEmail)) {
      setLocalError('Only @optiv.com or @gmail.com accounts are authorized.');
      return;
    }
    if (!password) {
      setLocalError('Please enter your security password.');
      return;
    }

    setSubmitting(true);
    try {
      await signInWithEmail(cleanEmail, password);
    } catch {
      // Handled in context
    } finally {
      setSubmitting(false);
    }
  };

  // 2. Initiate Registration (Send OTP)
  const handleInitiateRegistration = async (e: React.FormEvent) => {
    e.preventDefault();
    resetAllFields();

    const cleanEmail = email.trim();
    if (!cleanEmail) {
      setLocalError('Please enter your email address.');
      return;
    }
    if (!isOptivEmail(cleanEmail)) {
      setLocalError('Registration restricted: Only @optiv.com or @gmail.com email addresses are permitted.');
      return;
    }
    if (!password || password.length < 6) {
      setLocalError('Password must be at least 6 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setLocalError('Passwords do not match.');
      return;
    }

    setSubmitting(true);
    try {
      const result: VerificationResult = await initiateRegistration(cleanEmail, password, analystName);
      setLocalMessage(result.message);
      if (result.previewCode) {
        setActivePreviewCode(result.previewCode);
      }
      setVerificationCode('');
      setEmailView('register_verify');
    } catch (err: any) {
      setLocalError(err.message || 'Failed to send verification code.');
    } finally {
      setSubmitting(false);
    }
  };

  // 3. Confirm Registration (Verify OTP)
  const handleConfirmRegistration = async (e: React.FormEvent) => {
    e.preventDefault();
    resetAllFields();

    const cleanCode = verificationCode.trim();
    if (!cleanCode || cleanCode.length < 6) {
      setLocalError('Please enter the complete 6-digit verification code.');
      return;
    }

    setSubmitting(true);
    try {
      await confirmRegistration(email.trim(), cleanCode);
    } catch (err: any) {
      setLocalError(err.message || 'Verification failed.');
    } finally {
      setSubmitting(false);
    }
  };

  // 4. Initiate Password Reset (Send OTP)
  const handleInitiateReset = async (e: React.FormEvent) => {
    e.preventDefault();
    resetAllFields();

    const cleanEmail = email.trim();
    if (!cleanEmail) {
      setLocalError('Please enter your registered email address.');
      return;
    }
    if (!isOptivEmail(cleanEmail)) {
      setLocalError('Only @optiv.com or @gmail.com accounts are authorized.');
      return;
    }

    setSubmitting(true);
    try {
      const result: VerificationResult = await initiatePasswordReset(cleanEmail);
      setLocalMessage(result.message);
      if (result.previewCode) {
        setActivePreviewCode(result.previewCode);
      }
      setVerificationCode('');
      setPassword('');
      setConfirmPassword('');
      setEmailView('forgot_verify');
    } catch (err: any) {
      setLocalError(err.message || 'Failed to dispatch password reset code.');
    } finally {
      setSubmitting(false);
    }
  };

  // 5. Confirm Password Reset (Verify OTP & Set New Password)
  const handleConfirmReset = async (e: React.FormEvent) => {
    e.preventDefault();
    resetAllFields();

    const cleanCode = verificationCode.trim();
    if (!cleanCode || cleanCode.length < 6) {
      setLocalError('Please enter the 6-digit reset code.');
      return;
    }
    if (!password || password.length < 6) {
      setLocalError('New password must be at least 6 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setLocalError('New passwords do not match.');
      return;
    }

    setSubmitting(true);
    try {
      const successMsg = await confirmPasswordReset(email.trim(), cleanCode, password);
      setLocalMessage(successMsg);
      setEmailView('reset_success');
    } catch (err: any) {
      setLocalError(err.message || 'Password reset confirmation failed.');
    } finally {
      setSubmitting(false);
    }
  };

  const isEmailDomainValid = !email || isOptivEmail(email);

  return (
    <div className="min-h-screen bg-[#070A10] text-slate-100 flex flex-col justify-between selection:bg-cyan-500 selection:text-black relative overflow-hidden font-sans">
      {/* Background Cyber Grid & Glows */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b0f_1px,transparent_1px),linear-gradient(to_bottom,#1e293b0f_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none" />
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-violet-500/10 rounded-full blur-3xl pointer-events-none" />

      {/* Top Bar */}
      <header className="relative z-10 border-b border-slate-800/80 bg-[#0A0E17]/80 backdrop-blur-md px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-violet-500/20 border border-cyan-500/40 shadow-[0_0_15px_rgba(34,211,238,0.2)]">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <span className="absolute -bottom-1 -right-1 w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold tracking-wider text-sm text-slate-100 uppercase">
                OPTIV S.T.O.R.M
              </span>
              <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-violet-950/80 text-violet-300 border border-violet-800/60 flex items-center gap-1">
                <Sparkles className="w-2.5 h-2.5 text-violet-400" />
                ThreatLense AI
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              SOC Security Gateway · Authorized Personnel Only
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] font-mono text-cyan-400">
          <Building2 className="w-3 h-3 text-cyan-400" />
          <span>OPTIV & GMAIL AUTHORIZED</span>
        </div>
      </header>

      {/* Main Content Card */}
      <main className="relative z-10 flex-1 flex items-center justify-center p-4 sm:p-6 my-4">
        <div className="w-full max-w-lg bg-slate-900/90 border border-slate-800/90 rounded-2xl shadow-2xl p-6 sm:p-8 backdrop-blur-xl relative overflow-hidden">
          {/* Subtle top edge glow */}
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-violet-500 to-cyan-500" />

          {/* Badge & Title */}
          <div className="text-center mb-5">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 mb-3 shadow-[0_0_20px_rgba(34,211,238,0.15)]">
              <Fingerprint className="w-7 h-7 text-cyan-400" />
            </div>
            <h1 className="text-xl sm:text-2xl font-black text-slate-100 uppercase tracking-wider">
              Analyst Access Portal
            </h1>
            <div className="mt-1.5 inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-950/70 border border-cyan-800/60 text-[11px] font-mono text-cyan-300">
              <Lock className="w-3 h-3 text-cyan-400" />
              <span>@optiv.com & @gmail.com credentials authorized</span>
            </div>
          </div>

          {/* Top Auth Method Selector Tabs (Only when in normal sign-in modes) */}
          {(emailView === 'sign_in' || emailView === 'register_initiate') && (
            <div className="flex items-center rounded-xl bg-slate-950/80 p-1 border border-slate-800 mb-5">
              <button
                type="button"
                onClick={() => {
                  setAuthMethod('google');
                  resetAllFields();
                }}
                className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all flex items-center justify-center gap-2 cursor-pointer ${
                  authMethod === 'google'
                    ? 'bg-slate-800 text-cyan-300 shadow-sm border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24">
                  <path
                    fill="#4285F4"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                  />
                </svg>
                <span>Sign in with Google</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setAuthMethod('email');
                  resetAllFields();
                }}
                className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all flex items-center justify-center gap-2 cursor-pointer ${
                  authMethod === 'email'
                    ? 'bg-slate-800 text-cyan-300 shadow-sm border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Mail className="w-3.5 h-3.5" />
                <span>Email Sign-In</span>
              </button>
            </div>
          )}

          {/* Domain Whitelist Notice for Google Flow */}
          {isUnauthorizedDomain && authMethod === 'google' && (
            <div className="mb-5 p-4 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-200 text-xs space-y-3">
              <div className="flex items-start gap-2.5">
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <h3 className="font-bold text-amber-300 text-sm">
                    Domain Whitelist Required for Google Sign-In
                  </h3>
                  <p className="text-[11px] text-amber-200/80 mt-1 leading-relaxed">
                    Add this app domain to your Firebase Authorized Domains to enable Google Sign-In, or use the <strong>Email Sign-In</strong> tab above.
                  </p>
                </div>
              </div>

              <div className="bg-slate-950/80 border border-amber-900/60 rounded-lg p-2.5 flex items-center justify-between gap-2">
                <span className="font-mono text-[11px] text-cyan-300 truncate select-all">
                  {currentDomain}
                </span>
                <button
                  type="button"
                  onClick={handleCopyDomain}
                  className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 font-mono text-[10px] flex items-center gap-1.5 shrink-0 transition-colors cursor-pointer"
                >
                  {copied ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy Domain</span>
                    </>
                  )}
                </button>
              </div>

              <div className="text-[11px] text-slate-300 font-mono">
                <a
                  href={firebaseSettingsUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 underline font-semibold"
                >
                  <span>Open Firebase Auth Settings (Add Domain)</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          )}

          {/* Active Preview Code Helper (Shown if SMTP is not configured in env) */}
          {activePreviewCode && (
            <div className="mb-5 p-3.5 rounded-xl bg-cyan-950/70 border border-cyan-500/60 text-cyan-200 text-xs space-y-1.5 animate-fadeIn">
              <div className="flex items-center gap-2 text-cyan-300 font-bold">
                <Info className="w-4 h-4 text-cyan-400" />
                <span>Security Dispatch Helper</span>
              </div>
              <p className="text-[11px] text-cyan-100/90 leading-relaxed">
                Your 6-digit verification code is:
              </p>
              <div className="py-1 px-3 bg-slate-950 rounded-lg border border-cyan-500/40 font-mono text-center text-lg font-black tracking-widest text-cyan-300 select-all">
                {activePreviewCode}
              </div>
              <p className="text-[10px] text-cyan-300/70 font-mono">
                {smtpStatus.configured
                  ? 'Also dispatched to your email inbox via SMTP.'
                  : 'ℹ️ Real SMTP is not yet configured in environment variables. Code displayed here for seamless access.'}
              </p>
            </div>
          )}

          {/* Error Message Display */}
          {(localError || authError) && (
            <div className="mb-5 p-3.5 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <span className="font-semibold block mb-0.5">Authorization Notice</span>
                <p className="text-[11px] text-rose-200 leading-relaxed">
                  {localError || authError}
                </p>
              </div>
            </div>
          )}

          {/* Success Message Banner */}
          {localMessage && !localError && (
            <div className="mb-5 p-3 rounded-xl bg-emerald-950/60 border border-emerald-800/80 text-emerald-300 text-xs flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <p className="text-[11px] leading-relaxed">{localMessage}</p>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 1: GOOGLE SIGN-IN                                                     */}
          {/* ========================================================================= */}
          {authMethod === 'google' && (
            <div className="space-y-4">
              <button
                type="button"
                onClick={handleGoogleLogin}
                disabled={submitting}
                className="w-full py-3.5 px-4 rounded-xl bg-slate-100 hover:bg-white text-slate-900 font-semibold text-sm transition-all shadow-[0_0_20px_rgba(255,255,255,0.1)] hover:shadow-[0_0_25px_rgba(34,211,238,0.3)] flex items-center justify-center gap-3 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed group"
              >
                {submitting ? (
                  <>
                    <div className="w-4 h-4 border-2 border-slate-900 border-t-transparent rounded-full animate-spin" />
                    <span>Verifying Account...</span>
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                      <path
                        fill="#4285F4"
                        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                      />
                      <path
                        fill="#34A853"
                        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                      />
                      <path
                        fill="#FBBC05"
                        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                      />
                      <path
                        fill="#EA4335"
                        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                      />
                    </svg>
                    <span>Sign in with Google</span>
                    <ArrowRight className="w-4 h-4 text-slate-700 group-hover:translate-x-0.5 transition-transform" />
                  </>
                )}
              </button>

              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-[11px] text-slate-400 font-mono text-center">
                <span>Accepts </span>
                <strong className="text-cyan-300">@optiv.com</strong>
                <span> and </span>
                <strong className="text-cyan-300">@gmail.com</strong>
                <span> accounts.</span>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 2: EMAIL AUTH FLOWS                                                   */}
          {/* ========================================================================= */}
          {authMethod === 'email' && (
            <div>
              {/* --- VIEW 1: SIGN IN --- */}
              {emailView === 'sign_in' && (
                <form onSubmit={handleEmailSignIn} className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                      Authorized Email Address
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => {
                          setEmail(e.target.value);
                          if (localError) setLocalError(null);
                        }}
                        placeholder="analyst@optiv.com or user@gmail.com"
                        required
                        className={`w-full bg-slate-950 border rounded-xl pl-9 pr-32 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none font-mono ${
                          !isEmailDomainValid
                            ? 'border-rose-500 focus:border-rose-400'
                            : 'border-slate-700 focus:border-cyan-500'
                        }`}
                      />
                      <span className="absolute right-2.5 top-2.5 text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-cyan-400">
                        optiv / gmail
                      </span>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <label className="block text-xs font-semibold text-slate-300 font-mono">
                        Security Password
                      </label>
                      <button
                        type="button"
                        onClick={() => {
                          resetAllFields();
                          setEmailView('forgot_request');
                        }}
                        className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 underline cursor-pointer"
                      >
                        Forgot Password?
                      </button>
                    </div>
                    <div className="relative">
                      <KeyRound className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter your security password..."
                        required
                        className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-slate-950 font-bold text-xs uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(34,211,238,0.25)] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    {submitting ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                        <span>Authenticating...</span>
                      </>
                    ) : (
                      <>
                        <Lock className="w-3.5 h-3.5" />
                        <span>Sign In</span>
                      </>
                    )}
                  </button>

                  <div className="text-center pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        resetAllFields();
                        setEmailView('register_initiate');
                      }}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300 underline cursor-pointer"
                    >
                      First time analyst? Register with @optiv.com or @gmail.com
                    </button>
                  </div>
                </form>
              )}

              {/* --- VIEW 2: REGISTER INITIATE --- */}
              {emailView === 'register_initiate' && (
                <form onSubmit={handleInitiateRegistration} className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                      Analyst Callsign / Full Name
                    </label>
                    <div className="relative">
                      <User className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                      <input
                        type="text"
                        value={analystName}
                        onChange={(e) => setAnalystName(e.target.value)}
                        placeholder="e.g. Alex Vance"
                        required
                        className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                      Authorized Email (@optiv.com or @gmail.com)
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => {
                          setEmail(e.target.value);
                          if (localError) setLocalError(null);
                        }}
                        placeholder="analyst@optiv.com or user@gmail.com"
                        required
                        className={`w-full bg-slate-950 border rounded-xl pl-9 pr-32 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none font-mono ${
                          !isEmailDomainValid
                            ? 'border-rose-500 focus:border-rose-400'
                            : 'border-slate-700 focus:border-cyan-500'
                        }`}
                      />
                      <span className="absolute right-2.5 top-2.5 text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-cyan-400">
                        optiv / gmail
                      </span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                      Create Password (min. 6 characters)
                    </label>
                    <div className="relative">
                      <KeyRound className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Choose a strong password..."
                        required
                        className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                      Confirm Password
                    </label>
                    <div className="relative">
                      <KeyRound className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                      <input
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Confirm your password..."
                        required
                        className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-slate-950 font-bold text-xs uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(34,211,238,0.25)] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    {submitting ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                        <span>Sending 6-Digit Code...</span>
                      </>
                    ) : (
                      <>
                        <Mail className="w-3.5 h-3.5" />
                        <span>Send 6-Digit Verification Code</span>
                      </>
                    )}
                  </button>

                  <div className="text-center pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        resetAllFields();
                        setEmailView('sign_in');
                      }}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300 underline cursor-pointer"
                    >
                      Already registered? Sign In
                    </button>
                  </div>
                </form>
              )}

              {/* --- VIEW 3: REGISTER VERIFY OTP --- */}
              {emailView === 'register_verify' && (
                <form onSubmit={handleConfirmRegistration} className="space-y-4">
                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-center">
                    <p className="text-xs text-slate-300 font-mono">
                      Enter the 6-digit validation code sent to:
                    </p>
                    <p className="text-xs font-mono font-bold text-cyan-400 mt-0.5 truncate">
                      {email}
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono text-center">
                      6-Digit Security Code
                    </label>
                    <input
                      type="text"
                      maxLength={6}
                      value={verificationCode}
                      onChange={(e) => {
                        const val = e.target.value.replace(/\D/g, '');
                        setVerificationCode(val);
                        if (localError) setLocalError(null);
                      }}
                      placeholder="000000"
                      autoFocus
                      required
                      className="w-full bg-slate-950 border border-cyan-500/50 rounded-xl py-3 text-center text-2xl font-mono font-black tracking-widest text-cyan-300 placeholder-slate-600 focus:outline-none focus:border-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.15)]"
                    />
                    <p className="text-[10px] text-slate-500 font-mono text-center mt-1">
                      Code valid for 10 minutes.
                    </p>
                  </div>

                  <button
                    type="submit"
                    disabled={submitting || verificationCode.length < 6}
                    className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-slate-950 font-bold text-xs uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(34,211,238,0.25)] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    {submitting ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                        <span>Verifying Code...</span>
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Validate Code & Enter Console</span>
                      </>
                    )}
                  </button>

                  <div className="flex items-center justify-between pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        resetAllFields();
                        setEmailView('register_initiate');
                      }}
                      className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1 cursor-pointer"
                    >
                      <ArrowLeft className="w-3.5 h-3.5" />
                      <span>Back</span>
                    </button>

                    <button
                      type="button"
                      onClick={handleInitiateRegistration}
                      disabled={submitting}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1 cursor-pointer disabled:opacity-50"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>Resend Code</span>
                    </button>
                  </div>
                </form>
              )}

              {/* --- VIEW 4: FORGOT PASSWORD REQUEST --- */}
              {emailView === 'forgot_request' && (
                <form onSubmit={handleInitiateReset} className="space-y-4">
                  <div className="text-center mb-1">
                    <h2 className="text-sm font-bold text-slate-200">
                      Reset Security Password
                    </h2>
                    <p className="text-[11px] text-slate-400 mt-1">
                      Enter your registered email to receive a 6-digit password reset code.
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                      Registered Email Address
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => {
                          setEmail(e.target.value);
                          if (localError) setLocalError(null);
                        }}
                        placeholder="analyst@optiv.com or user@gmail.com"
                        required
                        className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-slate-950 font-bold text-xs uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(34,211,238,0.25)] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    {submitting ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                        <span>Sending Reset Code...</span>
                      </>
                    ) : (
                      <>
                        <Mail className="w-3.5 h-3.5" />
                        <span>Send Password Reset Code</span>
                      </>
                    )}
                  </button>

                  <div className="text-center pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        resetAllFields();
                        setEmailView('sign_in');
                      }}
                      className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center justify-center gap-1 mx-auto cursor-pointer"
                    >
                      <ArrowLeft className="w-3.5 h-3.5" />
                      <span>Return to Sign In</span>
                    </button>
                  </div>
                </form>
              )}

              {/* --- VIEW 5: FORGOT PASSWORD VERIFY & RESET --- */}
              {emailView === 'forgot_verify' && (
                <form onSubmit={handleConfirmReset} className="space-y-4">
                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-center">
                    <p className="text-xs text-slate-300 font-mono">
                      Enter the reset code sent to:
                    </p>
                    <p className="text-xs font-mono font-bold text-cyan-400 mt-0.5 truncate">
                      {email}
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono text-center">
                      6-Digit Reset Code
                    </label>
                    <input
                      type="text"
                      maxLength={6}
                      value={verificationCode}
                      onChange={(e) => {
                        const val = e.target.value.replace(/\D/g, '');
                        setVerificationCode(val);
                        if (localError) setLocalError(null);
                      }}
                      placeholder="000000"
                      autoFocus
                      required
                      className="w-full bg-slate-950 border border-cyan-500/50 rounded-xl py-2.5 text-center text-xl font-mono font-black tracking-widest text-cyan-300 placeholder-slate-600 focus:outline-none focus:border-cyan-400"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                      New Security Password (min. 6 chars)
                    </label>
                    <div className="relative">
                      <KeyRound className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter new password..."
                        required
                        className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                      Confirm New Password
                    </label>
                    <div className="relative">
                      <KeyRound className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                      <input
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Confirm new password..."
                        required
                        className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={submitting || verificationCode.length < 6}
                    className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-slate-950 font-bold text-xs uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(34,211,238,0.25)] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    {submitting ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                        <span>Updating Password...</span>
                      </>
                    ) : (
                      <>
                        <Lock className="w-3.5 h-3.5" />
                        <span>Confirm & Reset Password</span>
                      </>
                    )}
                  </button>

                  <div className="flex items-center justify-between pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        resetAllFields();
                        setEmailView('forgot_request');
                      }}
                      className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1 cursor-pointer"
                    >
                      <ArrowLeft className="w-3.5 h-3.5" />
                      <span>Back</span>
                    </button>

                    <button
                      type="button"
                      onClick={handleInitiateReset}
                      disabled={submitting}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1 cursor-pointer disabled:opacity-50"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>Resend Code</span>
                    </button>
                  </div>
                </form>
              )}

              {/* --- VIEW 6: RESET SUCCESS --- */}
              {emailView === 'reset_success' && (
                <div className="text-center py-4 space-y-4">
                  <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                    <CheckCircle2 className="w-6 h-6" />
                  </div>
                  <div>
                    <h2 className="text-base font-bold text-slate-100">
                      Password Reset Complete!
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                      Your security password has been updated. You can now sign in with your new credentials.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      resetAllFields();
                      setEmailView('sign_in');
                    }}
                    className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-slate-950 font-bold text-xs uppercase tracking-wider cursor-pointer"
                  >
                    Sign In with New Password
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Security Features Checklist */}
          <div className="pt-5 mt-5 border-t border-slate-800 space-y-2">
            <div className="flex items-center gap-2.5 text-xs text-slate-400">
              <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>Multi-Factor OTP Email Verification</span>
            </div>
            <div className="flex items-center gap-2.5 text-xs text-slate-400">
              <Radio className="w-4 h-4 text-violet-400 shrink-0" />
              <span>Domain Isolation (@optiv.com & @gmail.com)</span>
            </div>
            <div className="flex items-center gap-2.5 text-xs text-slate-400">
              <Cpu className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>Self-Service Password Reset with Security Expiry</span>
            </div>
          </div>

          {/* Security & Audit Disclaimer */}
          <div className="mt-5 pt-4 border-t border-slate-800/80 text-center">
            <p className="text-[10px] font-mono text-slate-500 leading-relaxed">
              RESTRICTED ENTERPRISE APPLICATION. All authentication actions and sessions are monitored and logged.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="relative z-10 border-t border-slate-800/60 bg-[#0A0E17]/60 px-6 py-3 text-center text-xs text-slate-500 font-mono">
        OPTIV S.T.O.R.M ThreatLense AI · Unified Security Operations Center
      </footer>
    </div>
  );
};
