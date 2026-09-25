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
  Building2
} from 'lucide-react';
import { useAuth, isOptivEmail } from '../context/AuthContext.js';

export const LoginGate: React.FC = () => {
  const {
    signInWithGoogle,
    signInWithEmail,
    registerWithEmail,
    authError,
    isUnauthorizedDomain,
    currentHost,
    clearAuthError
  } = useAuth();

  // Mode: 'google' | 'email'
  const [authMethod, setAuthMethod] = useState<'google' | 'email'>('google');
  const [isRegistering, setIsRegistering] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [copied, setCopied] = useState(false);

  // Form fields for email login
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [analystName, setAnalystName] = useState('');
  const [localEmailError, setLocalEmailError] = useState('');

  const currentDomain =
    currentHost || (typeof window !== 'undefined' ? window.location.hostname : '');
  const firebaseSettingsUrl =
    'https://console.firebase.google.com/project/gen-lang-client-0906610882/authentication/settings';
  const firebaseProvidersUrl =
    'https://console.firebase.google.com/project/gen-lang-client-0906610882/authentication/providers';

  const handleCopyDomain = () => {
    if (navigator?.clipboard && currentDomain) {
      navigator.clipboard.writeText(currentDomain);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  const handleGoogleLogin = async () => {
    clearAuthError();
    setLocalEmailError('');
    setSubmitting(true);
    try {
      await signInWithGoogle();
    } catch {
      // Handled in auth context
    } finally {
      setSubmitting(false);
    }
  };

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearAuthError();
    setLocalEmailError('');

    const cleanEmail = email.trim();
    if (!cleanEmail) {
      setLocalEmailError('Please enter your @optiv.com or @gmail.com email address.');
      return;
    }

    if (!isOptivEmail(cleanEmail)) {
      setLocalEmailError('Only email addresses ending in @optiv.com or @gmail.com are accepted.');
      return;
    }

    if (!password || password.length < 6) {
      setLocalEmailError('Password must be at least 6 characters.');
      return;
    }

    setSubmitting(true);
    try {
      if (isRegistering) {
        await registerWithEmail(cleanEmail, password, analystName.trim());
      } else {
        await signInWithEmail(cleanEmail, password);
      }
    } catch {
      // Handled in context
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

          {/* Auth Method Selector Tabs */}
          <div className="flex items-center rounded-xl bg-slate-950/80 p-1 border border-slate-800 mb-5">
            <button
              type="button"
              onClick={() => {
                setAuthMethod('google');
                clearAuthError();
                setLocalEmailError('');
              }}
              className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all flex items-center justify-center gap-2 cursor-pointer ${
                authMethod === 'google'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {/* Google SVG */}
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
                clearAuthError();
                setLocalEmailError('');
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

          {/* Unauthorized Domain Guide Panel (Google Flow) */}
          {isUnauthorizedDomain && authMethod === 'google' && (
            <div className="mb-5 p-4 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-200 text-xs space-y-3">
              <div className="flex items-start gap-2.5">
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <h3 className="font-bold text-amber-300 text-sm">
                    Domain Whitelist Required for Google Sign-In
                  </h3>
                  <p className="text-[11px] text-amber-200/80 mt-1 leading-relaxed">
                    Add this app domain to your Firebase Authorized Domains to enable Google Sign-In, or switch to the <strong>Email Sign-In</strong> tab above.
                  </p>
                </div>
              </div>

              {/* Hostname with 1-click Copy */}
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

              {/* Direct Link */}
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

          {/* Error Message Display */}
          {(authError || localEmailError) && (!isUnauthorizedDomain || authMethod === 'email') && (
            <div className="mb-5 p-3.5 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <span className="font-semibold block mb-0.5">Authorization Error</span>
                <p className="text-[11px] text-rose-200 leading-relaxed">
                  {localEmailError || authError}
                </p>
                {authError?.includes('Firebase Console') && (
                  <a
                    href={firebaseProvidersUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-cyan-300 underline mt-1.5 text-[10px] font-mono"
                  >
                    <span>Enable Email/Password in Firebase Console</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </div>
          )}

          {/* METHOD 1: Google Sign In */}
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

          {/* METHOD 2: Authorized Email Login */}
          {authMethod === 'email' && (
            <form onSubmit={handleEmailSubmit} className="space-y-4">
              {isRegistering && (
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                    SOC Analyst Callsign / Full Name
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
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Authorized Email Address (@optiv.com or @gmail.com)
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      if (localEmailError) setLocalEmailError('');
                    }}
                    placeholder="analyst@optiv.com or user@gmail.com"
                    required
                    className={`w-full bg-slate-950 border rounded-xl pl-9 pr-36 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none font-mono ${
                      !isEmailDomainValid
                        ? 'border-rose-500 focus:border-rose-400'
                        : 'border-slate-700 focus:border-cyan-500'
                    }`}
                  />
                  <span className="absolute right-2.5 top-2.5 text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-cyan-400">
                    optiv / gmail
                  </span>
                </div>
                {!isEmailDomainValid && (
                  <p className="text-[10px] text-rose-400 mt-1 font-mono">
                    * Domain must end with @optiv.com or @gmail.com
                  </p>
                )}
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Security Password
                </label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter security password..."
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
                    <span>Processing Authorization...</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-3.5 h-3.5" />
                    <span>{isRegistering ? 'Register Analyst Account' : 'Authenticate with Email'}</span>
                  </>
                )}
              </button>

              {/* Toggle Register / Sign In */}
              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setIsRegistering(!isRegistering);
                    clearAuthError();
                    setLocalEmailError('');
                  }}
                  className="text-xs font-mono text-cyan-400 hover:text-cyan-300 underline cursor-pointer"
                >
                  {isRegistering
                    ? 'Already have an account? Sign In'
                    : 'First time analyst? Register with your @optiv.com or @gmail.com email'}
                </button>
              </div>
            </form>
          )}

          {/* Security Features Checklist */}
          <div className="pt-5 mt-5 border-t border-slate-800 space-y-2">
            <div className="flex items-center gap-2.5 text-xs text-slate-400">
              <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>Corporate Domain Isolation (optiv.com)</span>
            </div>
            <div className="flex items-center gap-2.5 text-xs text-slate-400">
              <Radio className="w-4 h-4 text-violet-400 shrink-0" />
              <span>7-Engine Live Threat Feeds with AI Synthesis</span>
            </div>
            <div className="flex items-center gap-2.5 text-xs text-slate-400">
              <Cpu className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>Analyst Attribution & Automated 24-hr Purge</span>
            </div>
          </div>

          {/* Security & Audit Disclaimer */}
          <div className="mt-5 pt-4 border-t border-slate-800/80 text-center">
            <p className="text-[10px] font-mono text-slate-500 leading-relaxed">
              RESTRICTED ENTERPRISE APPLICATION. Unauthorized access attempts are monitored and logged. All session telemetry is tied to your verified Optiv identity.
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
