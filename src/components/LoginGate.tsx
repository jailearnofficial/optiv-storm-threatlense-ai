import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Sparkles,
  ArrowRight,
  Radio,
  FileCheck2,
  Cpu,
  AlertTriangle,
  Fingerprint
} from 'lucide-react';
import { useAuth } from '../context/AuthContext.js';

export const LoginGate: React.FC = () => {
  const { signInWithGoogle, authError, clearAuthError } = useAuth();
  const [signingIn, setSigningIn] = useState(false);

  const handleLogin = async () => {
    clearAuthError();
    setSigningIn(true);
    try {
      await signInWithGoogle();
    } catch {
      // Error handled in auth context
    } finally {
      setSigningIn(false);
    }
  };

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
              SOC Security Gateway & Access Control
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] font-mono text-cyan-400">
          <Lock className="w-3 h-3 text-cyan-400" />
          <span>FIREBASE AUTH SECURED</span>
        </div>
      </header>

      {/* Main Content Card */}
      <main className="relative z-10 flex-1 flex items-center justify-center p-4 sm:p-6">
        <div className="w-full max-w-md bg-slate-900/90 border border-slate-800/90 rounded-2xl shadow-2xl p-6 sm:p-8 backdrop-blur-xl relative overflow-hidden">
          {/* Subtle top edge glow */}
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-violet-500 to-cyan-500" />

          {/* Badge & Title */}
          <div className="text-center mb-6">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 mb-4 shadow-[0_0_20px_rgba(34,211,238,0.15)]">
              <Fingerprint className="w-7 h-7 text-cyan-400" />
            </div>
            <h1 className="text-xl sm:text-2xl font-black text-slate-100 uppercase tracking-wider">
              Analyst Access Portal
            </h1>
            <p className="text-xs text-slate-400 mt-1.5 font-mono">
              Verify identity to access unified threat intelligence and AI synthesis
            </p>
          </div>

          {/* Auth Error Display */}
          {authError && (
            <div className="mb-5 p-3 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <span className="font-semibold block mb-0.5">Authentication Failed</span>
                <p className="text-[11px] text-rose-200 leading-relaxed">{authError}</p>
              </div>
            </div>
          )}

          {/* Sign In Button */}
          <div className="space-y-4">
            <button
              onClick={handleLogin}
              disabled={signingIn}
              className="w-full py-3.5 px-4 rounded-xl bg-slate-100 hover:bg-white text-slate-900 font-semibold text-sm transition-all shadow-[0_0_20px_rgba(255,255,255,0.1)] hover:shadow-[0_0_25px_rgba(34,211,238,0.3)] flex items-center justify-center gap-3 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed group"
            >
              {signingIn ? (
                <>
                  <div className="w-4 h-4 border-2 border-slate-900 border-t-transparent rounded-full animate-spin" />
                  <span>Authorizing SOC Session...</span>
                </>
              ) : (
                <>
                  {/* Google SVG Icon */}
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

            {/* Feature Highlights */}
            <div className="pt-4 border-t border-slate-800 space-y-2.5">
              <div className="flex items-center gap-2.5 text-xs text-slate-400">
                <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>Zero-Trust RBAC & Session Attribution</span>
              </div>
              <div className="flex items-center gap-2.5 text-xs text-slate-400">
                <Radio className="w-4 h-4 text-violet-400 shrink-0" />
                <span>7-Engine Parallel Threat Telemetry</span>
              </div>
              <div className="flex items-center gap-2.5 text-xs text-slate-400">
                <Cpu className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>Gemini 2.5 Multi-Provider AI Synthesis</span>
              </div>
            </div>
          </div>

          {/* Security & Audit Disclaimer */}
          <div className="mt-6 pt-4 border-t border-slate-800/80 text-center">
            <p className="text-[10px] font-mono text-slate-500 leading-relaxed">
              CONFIDENTIAL & RESTRICTED ACCESS. All actions and IOC submissions are logged under the authenticated analyst profile with a strict 24-hour retention window.
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
