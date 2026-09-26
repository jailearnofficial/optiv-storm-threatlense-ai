/**
 * Server Configuration & Secret Management
 * Section 9: API keys loaded from environment, never exposed to browser
 */

import dotenv from 'dotenv';
dotenv.config();

export interface ServerConfig {
  geminiApiKey: string;
  vtApiKey: string;
  haApiKey: string;
  abusechAuthKey: string;
  abuseipdbApiKey: string;
  urlscanApiKey: string;
  otxApiKey: string;
  port: number;
  modelName: string;
}

export const config: ServerConfig = {
  geminiApiKey: process.env.GEMINI_API_KEY || '',
  vtApiKey: process.env.VT_API_KEY || '',
  haApiKey: process.env.HA_API_KEY || '',
  abusechAuthKey: process.env.ABUSECH_AUTH_KEY || '',
  abuseipdbApiKey: process.env.ABUSEIPDB_API_KEY || '',
  urlscanApiKey: process.env.URLSCAN_API_KEY || '',
  otxApiKey: process.env.OTX_API_KEY || '',
  port: parseInt(process.env.PORT || '3000', 10),
  modelName: 'gemini-3.8-flash',
};

export function getProviderHealth(): Record<string, { configured: boolean; status: 'up' | 'limited' | 'mock' }> {
  return {
    virustotal: {
      configured: Boolean(config.vtApiKey),
      status: config.vtApiKey ? 'up' : 'mock'
    },
    hybrid_analysis: {
      configured: Boolean(config.haApiKey),
      status: config.haApiKey ? 'up' : 'mock'
    },
    malwarebazaar: {
      configured: Boolean(config.abusechAuthKey),
      status: config.abusechAuthKey ? 'up' : 'up' // Abuse.ch has open search API
    },
    abuseipdb: {
      configured: Boolean(config.abuseipdbApiKey),
      status: config.abuseipdbApiKey ? 'up' : 'mock'
    },
    urlhaus: {
      configured: Boolean(config.abusechAuthKey),
      status: config.abusechAuthKey ? 'up' : 'up' // URLhaus has open search API
    },
    urlscan: {
      configured: Boolean(config.urlscanApiKey),
      status: config.urlscanApiKey ? 'up' : 'up' // urlscan search API has free public access
    },
    alienvault_otx: {
      configured: Boolean(config.otxApiKey),
      status: config.otxApiKey ? 'up' : 'mock'
    }
  };
}
