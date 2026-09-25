import nodemailer, { Transporter } from 'nodemailer';

export interface SendMailResult {
  sentViaSmtp: boolean;
  messageId?: string;
  previewCode?: string;
  error?: string;
}

class MailerService {
  private transporter: Transporter | null = null;
  private isConfigured: boolean = false;

  constructor() {
    this.initTransporter();
  }

  private initTransporter() {
    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT || '587', 10);
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;
    const secure = process.env.SMTP_SECURE === 'true' || port === 465;

    if (host && user && pass) {
      try {
        this.transporter = nodemailer.createTransport({
          host,
          port,
          secure,
          auth: { user, pass }
        });
        this.isConfigured = true;
        console.log(`[OPTIV Mailer] Initialized SMTP transport for ${host}:${port} as ${user}`);
      } catch (err) {
        console.error('[OPTIV Mailer] Failed to initialize SMTP transport:', err);
        this.transporter = null;
        this.isConfigured = false;
      }
    } else {
      this.transporter = null;
      this.isConfigured = false;
      console.log('[OPTIV Mailer] No SMTP credentials configured. Email dispatch will run in simulated preview mode with console/UI telemetry.');
    }
  }

  public getStatus() {
    return {
      configured: this.isConfigured,
      host: process.env.SMTP_HOST ? 'Configured' : 'Not Set',
      user: process.env.SMTP_USER ? 'Configured' : 'Not Set',
      port: process.env.SMTP_PORT || '587'
    };
  }

  public async sendVerificationCode(toEmail: string, code: string, purpose: 'registration' | 'password_reset'): Promise<SendMailResult> {
    const subject = purpose === 'registration'
      ? `OPTIV S.T.O.R.M · Your 6-Digit Registration Code: ${code}`
      : `OPTIV S.T.O.R.M · Password Reset Verification Code: ${code}`;

    const title = purpose === 'registration'
      ? 'Analyst Registration Verification'
      : 'Security Password Reset Request';

    const actionText = purpose === 'registration'
      ? 'Please enter this verification code in the OPTIV S.T.O.R.M ThreatLense AI portal to complete your account registration:'
      : 'A password reset was requested for your account. Please enter this verification code to set your new security password:';

    const htmlBody = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #070A10; color: #E2E8F0; margin: 0; padding: 24px; }
          .container { max-width: 540px; margin: 0 auto; background-color: #0F172A; border: 1px solid #1E293B; border-radius: 12px; overflow: hidden; }
          .header { background: linear-gradient(135deg, #0A0E17 0%, #1E1B4B 100%); padding: 24px; border-bottom: 1px solid #334155; text-align: center; }
          .logo { font-size: 16px; font-weight: 900; letter-spacing: 2px; color: #22D3EE; text-transform: uppercase; }
          .subtitle { font-size: 11px; color: #94A3B8; margin-top: 4px; font-family: monospace; }
          .body { padding: 32px 24px; }
          .code-box { background-color: #020617; border: 2px solid #06B6D4; border-radius: 8px; padding: 18px; text-align: center; margin: 24px 0; }
          .code-digits { font-family: 'Courier New', Courier, monospace; font-size: 36px; font-weight: 900; letter-spacing: 8px; color: #38BDF8; }
          .timer-notice { font-size: 12px; color: #F59E0B; margin-top: 8px; }
          .footer { background-color: #0A0E17; padding: 16px 24px; border-top: 1px solid #1E293B; font-size: 11px; color: #64748B; text-align: center; line-height: 1.5; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">OPTIV S.T.O.R.M · ThreatLense AI</div>
            <div class="subtitle">Unified SOC Threat Intelligence & Triage Console</div>
          </div>
          <div class="body">
            <h2 style="margin-top:0; color:#F8FAFC; font-size:18px;">${title}</h2>
            <p style="color:#CBD5E1; font-size:14px; line-height:1.6;">${actionText}</p>
            <div class="code-box">
              <div class="code-digits">${code}</div>
              <div class="timer-notice">⏱ Valid for 10 minutes only</div>
            </div>
            <p style="color:#94A3B8; font-size:12px; line-height:1.5;">
              If you did not initiate this request, notify your SOC administrator immediately. Do not share this code with anyone.
            </p>
          </div>
          <div class="footer">
            RESTRICTED ENTERPRISE APPLICATION · OPTIV S.T.O.R.M SEC-OPS<br/>
            This is an automated dispatch. Replies to this address are not monitored.
          </div>
        </div>
      </body>
      </html>
    `;

    // Attempt real SMTP send if configured
    if (this.isConfigured && this.transporter) {
      try {
        const fromAddress = process.env.SMTP_FROM || 'OPTIV S.T.O.R.M <noreply@optiv.com>';
        const info = await this.transporter.sendMail({
          from: fromAddress,
          to: toEmail,
          subject,
          text: `${title}\n\n${actionText}\n\nVerification Code: ${code}\n\nThis code will expire in 10 minutes.\n\nRESTRICTED ENTERPRISE APPLICATION`,
          html: htmlBody
        });
        console.log(`[OPTIV Mailer] Sent verification email to ${toEmail} (Message ID: ${info.messageId})`);
        return { sentViaSmtp: true, messageId: info.messageId };
      } catch (err: any) {
        console.error(`[OPTIV Mailer] Failed to send via SMTP to ${toEmail}:`, err.message);
        // Fall back to returning previewCode so user isn't stuck
        return {
          sentViaSmtp: false,
          error: `SMTP error: ${err.message}`,
          previewCode: code
        };
      }
    }

    // SMTP not configured -> Provide preview code for seamless developer/testing experience
    console.log(`[OPTIV Mailer DEV NOTICE] Simulated email dispatch to ${toEmail}: Code is ${code}`);
    return {
      sentViaSmtp: false,
      previewCode: code
    };
  }
}

export const mailer = new MailerService();
