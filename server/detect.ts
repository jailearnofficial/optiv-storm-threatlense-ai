/**
 * Indicator Type Detection and Defang/Refang Utility
 * According to Section 3 of SOC Analysis Design Spec
 */

export type IndicatorType = 'hash' | 'ip' | 'url' | 'domain';

export interface DetectionResult {
  valid: boolean;
  type: IndicatorType;
  normalized: string;
  defanged: string;
  error?: string;
  hashType?: 'md5' | 'sha1' | 'sha256';
}

// Private / loopback / reserved IPv4 ranges
const PRIVATE_IP_REGEXES = [
  /^127\./,                                     // 127.0.0.0/8 (Loopback)
  /^10\./,                                      // 10.0.0.0/8 (Private)
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,             // 172.16.0.0/12 (Private)
  /^192\.168\./,                                // 192.168.0.0/16 (Private)
  /^169\.254\./,                                // 169.254.0.0/16 (Link Local)
  /^0\./,                                       // 0.0.0.0/8
  /^(22[4-9]|23[0-9])\./,                       // Multicast
  /^255\.255\.255\.255$/,                       // Broadcast
  /^::1$/,                                      // IPv6 Loopback
  /^fc00:/i,                                    // IPv6 Unique Local
  /^fe80:/i,                                    // IPv6 Link-Local
];

export function refang(input: string): string {
  if (!input) return '';
  let str = input.trim();
  // hxxp:// or hxxps:// or fxp://
  str = str.replace(/^hxxp(s?):\/\//i, 'http$1://');
  str = str.replace(/^fxp:\/\//i, 'ftp://');
  // [.] or (.) or {.} -> .
  str = str.replace(/\[\.\]/g, '.');
  str = str.replace(/\(\.\)/g, '.');
  str = str.replace(/\{\.\}/g, '.');
  // [:] -> :
  str = str.replace(/\[:\]/g, ':');
  return str;
}

export function defang(input: string, type?: IndicatorType): string {
  if (!input) return '';
  let str = input.trim();

  // If already defanged, normalize it
  const refanged = refang(str);

  if (type === 'url' || /^https?:\/\//i.test(refanged)) {
    return refanged
      .replace(/^https:\/\//i, 'hxxps://')
      .replace(/^http:\/\//i, 'hxxp://')
      .replace(/\./g, '[.]');
  }

  if (type === 'ip') {
    return refanged.replace(/\./g, '[.]');
  }

  if (type === 'domain') {
    return refanged.replace(/\./g, '[.]');
  }

  // Generic defang
  return refanged
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/(\w+)\.(\w+)/g, '$1[.]$2');
}

export function detectIndicatorType(rawInput: string, overrideType?: string): DetectionResult {
  const input = rawInput.trim();

  if (!input) {
    return {
      valid: false,
      type: 'domain',
      normalized: '',
      defanged: '',
      error: 'Indicator cannot be empty.'
    };
  }

  if (input.length > 2048) {
    return {
      valid: false,
      type: 'domain',
      normalized: '',
      defanged: '',
      error: 'Indicator exceeds maximum allowed length of 2,048 characters.'
    };
  }

  const clean = refang(input);

  // 1. File Hash Check: hex string of 32 (MD5), 40 (SHA-1), 64 (SHA-256)
  const isHexOnly = /^[a-fA-F0-9]+$/.test(clean);
  if ((overrideType === 'hash' || !overrideType || overrideType === 'auto') && isHexOnly) {
    const len = clean.length;
    if (len === 32) {
      return {
        valid: true,
        type: 'hash',
        normalized: clean.toLowerCase(),
        defanged: clean.toLowerCase(),
        hashType: 'md5'
      };
    } else if (len === 40) {
      return {
        valid: true,
        type: 'hash',
        normalized: clean.toLowerCase(),
        defanged: clean.toLowerCase(),
        hashType: 'sha1'
      };
    } else if (len === 64) {
      return {
        valid: true,
        type: 'hash',
        normalized: clean.toLowerCase(),
        defanged: clean.toLowerCase(),
        hashType: 'sha256'
      };
    }
  }

  // 2. IP Address Check
  const ipv4Regex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:)$/;

  const isIpCandidate = ipv4Regex.test(clean) || ipv6Regex.test(clean);
  if ((overrideType === 'ip' || (!overrideType || overrideType === 'auto')) && isIpCandidate) {
    for (const r of PRIVATE_IP_REGEXES) {
      if (r.test(clean)) {
        return {
          valid: false,
          type: 'ip',
          normalized: clean,
          defanged: defang(clean, 'ip'),
          error: `Private, loopback, and reserved IP addresses (${clean}) are not queryable on public threat-intel feeds.`
        };
      }
    }
    return {
      valid: true,
      type: 'ip',
      normalized: clean,
      defanged: defang(clean, 'ip')
    };
  }

  // 3. URL Check
  const isUrlScheme = /^https?:\/\/|^ftp:\/\//i.test(clean);
  const hasPathSlash = clean.includes('/') && !clean.endsWith('/') && clean.indexOf('/') < clean.length - 1;
  if (overrideType === 'url' || (!overrideType || overrideType === 'auto' && (isUrlScheme || hasPathSlash))) {
    try {
      const urlCandidate = isUrlScheme ? clean : `http://${clean}`;
      const parsed = new URL(urlCandidate);
      
      // Enforce safe protocols only
      if (!['http:', 'https:', 'ftp:'].includes(parsed.protocol)) {
        return {
          valid: false,
          type: 'url',
          normalized: clean,
          defanged: defang(clean, 'url'),
          error: `Unsupported URL protocol '${parsed.protocol}'. Only HTTP, HTTPS, and FTP indicators are accepted.`
        };
      }

      const host = parsed.hostname.toLowerCase();
      // Block localhost, private IP ranges, and cloud metadata (169.254.x.x)
      if (host === 'localhost' || PRIVATE_IP_REGEXES.some((r) => r.test(host))) {
        return {
          valid: false,
          type: 'url',
          normalized: clean,
          defanged: defang(clean, 'url'),
          error: `URLs targeting private, loopback, or cloud metadata IP addresses (${host}) are forbidden.`
        };
      }

      if (parsed.hostname && parsed.hostname.includes('.')) {
        const normalized = clean;
        return {
          valid: true,
          type: 'url',
          normalized: normalized,
          defanged: defang(normalized, 'url')
        };
      }
    } catch {
      // Not a valid URL
    }
  }

  // 4. Domain Check
  // Valid FQDN, no scheme or path
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
  const cleanDomain = clean.replace(/\/+$/, '').toLowerCase();
  if (domainRegex.test(cleanDomain) || overrideType === 'domain') {
    return {
      valid: true,
      type: 'domain',
      normalized: cleanDomain,
      defanged: defang(cleanDomain, 'domain')
    };
  }

  // If forced override but failed
  if (overrideType && overrideType !== 'auto') {
    return {
      valid: false,
      type: overrideType as IndicatorType,
      normalized: clean,
      defanged: defang(clean),
      error: `Indicator does not match requested type '${overrideType}'.`
    };
  }

  return {
    valid: false,
    type: 'domain',
    normalized: clean,
    defanged: defang(clean),
    error: 'Unrecognized indicator format. Please enter a valid MD5/SHA-1/SHA-256 hash, IPv4/IPv6, FQDN domain, or URL.'
  };
}
