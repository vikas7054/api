import express from 'express';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { UserModel } from '../../models/user.model.js';

const router = express.Router();

// Email configuration
// Set RESEND_API_KEY in your .env / Vercel project settings — never hardcode it here.
const EMAIL_CONFIG = {
  API_KEY: process.env.RESEND_API_KEY || 're_JP7aGFzr_8i7QrL6DUqKfAodwzHsNEwVU',
  SENDER_EMAIL: process.env.RESEND_SENDER_EMAIL || 'onboarding@resend.dev',
  SENDER_NAME: 'Famx Team',
};

if (!EMAIL_CONFIG.API_KEY) {
  console.error('WARNING: RESEND_API_KEY is not set. Password reset emails will fail.');
}

// In-memory token storage (use database in production)
const resetTokens = new Map();

// Token management
const tokenManager = {
  generate(userId, email) {
    const token = uuidv4();
    const expires = Date.now() + 15 * 60 * 1000; // 15 minutes
    
    resetTokens.set(token, { userId, email, expires });
    return token;
  },

  validate(token) {
    const data = resetTokens.get(token);
    
    if (!data) {
      throw new Error('Invalid reset token');
    }
    
    if (Date.now() > data.expires) {
      resetTokens.delete(token);
      throw new Error('Reset token has expired');
    }
    
    return data;
  },

  remove(token) {
    resetTokens.delete(token);
  }
};

// Email service
const emailService = {
  async sendResetEmail(toEmail, username, resetToken) {
    const url = 'https://api.resend.com/emails';
    const resetUrl = `https://famous-liger-b17e21.netlify.app/forgot-password/code/${resetToken}`;

    const emailData = {
      from: `${EMAIL_CONFIG.SENDER_NAME} <${EMAIL_CONFIG.SENDER_EMAIL}>`,
      to: [toEmail],
      subject: 'Password Reset Request',
      text: this._getPlainText(username, resetToken, resetUrl),
      html: this._getHtml(username, resetToken, resetUrl),
    };

    try {
      await axios.post(url, emailData, {
        headers: {
          'Authorization': `Bearer ${EMAIL_CONFIG.API_KEY}`,
          'Content-Type': 'application/json',
        },
        timeout: 10000, // avoid a hung request blocking the function
      });
      return true;
    } catch (error) {
      console.error('Email sending failed:', error.response?.data || error.message);
      throw new Error('Failed to send reset email');
    }
  },

  _getPlainText(username, resetToken, resetUrl) {
    return `
      Hello ${username},

      We received a request to reset your password. Here's your password reset token:
      ${resetToken}

      Or click the following link to reset your password:
      ${resetUrl}

      This token will expire in 15 minutes.

      If you did not request this reset, please ignore this email.

      Best regards,
      ${EMAIL_CONFIG.SENDER_NAME}
    `;
  },

  _getHtml(username, resetToken, resetUrl) {
    const LOGO_URL = 'https://raw.githubusercontent.com/7054company/7eax/refs/heads/master/logo1.png';
    const year = new Date().getFullYear();

    return `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Reset your password</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f5f7; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f5f7; padding:40px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px; background-color:#ffffff; border-radius:16px; overflow:hidden; box-shadow:0 4px 24px rgba(15,23,42,0.06); border:1px solid #eef0f3;">

          <!-- Header / Logo -->
          <tr>
            <td style="background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%); padding:36px 40px; text-align:center;">
              <img src="${LOGO_URL}" alt="Famx Cloud" width="52" height="52" style="display:block; margin:0 auto 12px auto; border-radius:12px;" />
              <span style="display:inline-block; color:#ffffff; font-size:20px; font-weight:700; letter-spacing:0.3px;">Famx Cloud Platform</span>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:40px 40px 24px 40px;">
              <h1 style="margin:0 0 16px 0; font-size:22px; line-height:30px; color:#0f172a; font-weight:700;">
                Reset your password
              </h1>
              <p style="margin:0 0 20px 0; font-size:15px; line-height:24px; color:#475569;">
                Hi ${username || 'there'},
              </p>
              <p style="margin:0 0 28px 0; font-size:15px; line-height:24px; color:#475569;">
                We received a request to reset the password on your Famx Cloud account. Click the button below to choose a new password. This link is valid for the next <strong>15 minutes</strong>.
              </p>

              <!-- CTA Button -->
              <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 28px 0;">
                <tr>
                  <td style="border-radius:10px; background:linear-gradient(135deg,#2563eb 0%,#1d4ed8 100%);">
                    <a href="${resetUrl}"
                       style="display:inline-block; padding:14px 32px; font-size:15px; font-weight:600; color:#ffffff; text-decoration:none; border-radius:10px;">
                      Reset Password →
                    </a>
                  </td>
                </tr>
              </table>

              <p style="margin:0 0 8px 0; font-size:13px; line-height:20px; color:#94a3b8;">
                Or use this one-time reset code if the button doesn't work:
              </p>
              <div style="background-color:#f8fafc; border:1px dashed #cbd5e1; border-radius:8px; padding:14px 18px; margin:0 0 28px 0;">
                <code style="font-size:16px; letter-spacing:1px; color:#1e293b; font-weight:600; word-break:break-all;">${resetToken}</code>
              </div>

              <p style="margin:0 0 4px 0; font-size:13px; line-height:20px; color:#94a3b8;">
                If you didn't request this, you can safely ignore this email — your password will remain unchanged.
              </p>
            </td>
          </tr>

          <!-- Divider -->
          <tr>
            <td style="padding:0 40px;">
              <div style="border-top:1px solid #eef0f3;"></div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:24px 40px 32px 40px; text-align:center;">
              <p style="margin:0 0 6px 0; font-size:12px; color:#94a3b8;">
                Sent by <strong style="color:#64748b;">${EMAIL_CONFIG.SENDER_NAME}</strong> · Famx Cloud Platform
              </p>
              <p style="margin:0; font-size:12px; color:#cbd5e1;">
                A -101 Company · © ${year} All rights reserved.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    `;
  }
};

// Route handlers
router.get('/f/:identifier', async (req, res) => {
  const { identifier } = req.params;

  try {
    // Find user
    const user = await UserModel.findByEmail(identifier);
    if (!user) {
      return res.status(404).json({ 
        message: 'No account found with this email address' 
      });
    }

    // Generate reset token
    const resetToken = tokenManager.generate(user.id, user.email);

    // Send reset email
    await emailService.sendResetEmail(user.email, user.username, resetToken);

    res.json({ 
      message: 'Password reset instructions sent',
      email: user.email
    });

  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ 
      message: 'Error processing password reset request' 
    });
  }
});

router.post('/reset', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    // Validate token
    const resetData = tokenManager.validate(token);

    // Update password
    await UserModel.updatePassword(resetData.userId, newPassword);
    
    // Clear token
    tokenManager.remove(token);

    res.json({ 
      message: 'Password successfully reset' 
    });

  } catch (error) {
    console.error('Password reset error:', error);
    res.status(400).json({ 
      message: error.message || 'Error resetting password' 
    });
  }
});

export default router;
// at the bottom of that reset.js file
export { emailService };
