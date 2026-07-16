import { query } from '../../config/database.js';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

export const AuthXUserModel = {
  // Create a new user for an AuthX app
  async create({ appId, email, password, username = null }) {
    const userId = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const sql = `
      INSERT INTO authx_app_users (
        id, app_id, email, password, username, status,
        created_at, updated_at, logs
      ) VALUES (?, ?, ?, ?, ?, 'active', NOW(), NOW(), '{"ips":[],"activities":[]}')
    `;
    
    await query(sql, [userId, appId, email, hashedPassword, username]);
    return userId;
  },

  // Find user by email within an app
  async findByEmail(appId, email) {
    const sql = `
      SELECT * FROM authx_app_users
      WHERE app_id = ? AND email = ?
    `;
    
    const [user] = await query(sql, [appId, email]);
    return user || null;
  },

  // Find user by ID within an app
  async findById(appId, userId) {
    const sql = `
      SELECT id, email, username, status, created_at, updated_at, logs
      FROM authx_app_users
      WHERE app_id = ? AND id = ?
    `;
    
    const [user] = await query(sql, [appId, userId]);
    return user || null;
  },

  // Update user's tracking information
  async updateTracking(appId, userId, { ip, userAgent, type = 'login', timestamp = new Date().toISOString() }) {
    // Get current user data
    const user = await this.findById(appId, userId);
    if (!user) return null;

    // Parse current logs
    const logs = JSON.parse(user.logs || '{"ips":[],"activities":[]}');

    // Update IPs (keep only last 5)
    if (!logs.ips.includes(ip)) {
      logs.ips.unshift(ip);
      if (logs.ips.length > 5) logs.ips.pop();
    }

    // Parse user agent information
    const deviceInfo = this.parseUserAgent(userAgent);

    // Add new activity log entry
    const logEntry = {
      timestamp,
      ip,
      type,
      ...deviceInfo
    };

    // Keep only last 50 activities
    logs.activities.unshift(logEntry);
    if (logs.activities.length > 50) logs.activities.pop();

    // Update database
    const sql = `
      UPDATE authx_app_users
      SET 
        logs = ?,
        updated_at = NOW()
      WHERE app_id = ? AND id = ?
    `;

    await query(sql, [
      JSON.stringify(logs),
      appId,
      userId
    ]);

    return logs;
  },

  // Parse User-Agent string
  parseUserAgent(userAgent) {
    const info = {
      browser: 'Unknown',
      device: 'Unknown',
      os: 'Unknown'
    };

    try {
      // Basic browser detection
      if (userAgent.includes('Firefox/')) {
        info.browser = 'Firefox';
      } else if (userAgent.includes('Chrome/')) {
        info.browser = 'Chrome';
      } else if (userAgent.includes('Safari/')) {
        info.browser = 'Safari';
      } else if (userAgent.includes('Edge/')) {
        info.browser = 'Edge';
      }

      // Basic OS detection
      if (userAgent.includes('Windows')) {
        info.os = 'Windows';
      } else if (userAgent.includes('Mac OS X')) {
        info.os = 'macOS';
      } else if (userAgent.includes('Linux')) {
        info.os = 'Linux';
      } else if (userAgent.includes('Android')) {
        info.os = 'Android';
      } else if (userAgent.includes('iOS')) {
        info.os = 'iOS';
      }

      // Basic device detection
      if (userAgent.includes('Mobile')) {
        info.device = 'Mobile';
      } else if (userAgent.includes('Tablet')) {
        info.device = 'Tablet';
      } else {
        info.device = 'Desktop';
      }
    } catch (error) {
      console.error('Error parsing user agent:', error);
    }

    return info;
  },

  // Update user password
  // Stores the password as a bcrypt hash (10 salt rounds) — never plaintext.
  // Verifies that the UPDATE actually matched a row, since SQL UPDATEs
  // succeed silently even when WHERE matches nothing.
  async updatePassword(appId, userId, newPassword) {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const sql = `
      UPDATE authx_app_users
      SET password = ?, updated_at = NOW()
      WHERE app_id = ? AND id = ?
    `;

    const result = await query(sql, [hashedPassword, appId, userId]);

    // mysql2 returns [ResultSetHeader, fields] where ResultSetHeader.affectedRows
    // tells us how many rows were actually updated. Some query() wrappers
    // return the ResultSetHeader directly instead of wrapping it in an array.
    const affectedRows = Array.isArray(result)
      ? result[0]?.affectedRows
      : result?.affectedRows;

    if (typeof affectedRows === 'number' && affectedRows === 0) {
      console.error('updatePassword: 0 rows affected', { appId, userId });
      throw new Error('Password update did not match any user record');
    }

    // Sanity check: re-read the row and confirm the new hash actually verifies.
    const updatedUser = await this.findByIdWithPassword(appId, userId);
    if (!updatedUser || !(await bcrypt.compare(newPassword, updatedUser.password))) {
      console.error('updatePassword: verification failed after update', { appId, userId });
      throw new Error('Password update could not be verified');
    }

    return true;
  },

  // Like findById, but includes the password hash (needed only for internal
  // verification right after a password change — never expose this to a route).
  async findByIdWithPassword(appId, userId) {
    const sql = `
      SELECT id, password
      FROM authx_app_users
      WHERE app_id = ? AND id = ?
    `;

    const [user] = await query(sql, [appId, userId]);
    return user || null;
  },

  // Add password reset token
  async addResetToken(appId, userId, token, expires) {
    const sql = `
      INSERT INTO authx_password_resets (
        app_id, user_id, token, expires_at, created_at, used
      ) VALUES (?, ?, ?, ?, NOW(), 0)
    `;
    
    await query(sql, [appId, userId, token, expires]);
  },

  // Validate reset token
  async validateResetToken(appId, token) {
    const sql = `
      SELECT user_id
      FROM authx_password_resets
      WHERE app_id = ? AND token = ? AND expires_at > NOW()
      AND used = 0
    `;
    
    const [result] = await query(sql, [appId, token]);
    return result?.user_id || null;
  },

  // Mark reset token as used
  async markTokenUsed(appId, token) {
    const sql = `
      UPDATE authx_password_resets
      SET used = 1, updated_at = NOW()
      WHERE app_id = ? AND token = ?
    `;
    
    await query(sql, [appId, token]);
  },

  // Format user response
  formatUser(user) {
    if (!user) return null;
    
    const { password, ...userWithoutPassword } = user;
    if (userWithoutPassword.logs) {
      userWithoutPassword.logs = JSON.parse(userWithoutPassword.logs);
    }
    return userWithoutPassword;
  },

  // Get all users for an app
  async getAllUsers(appId) {
    const sql = `
      SELECT 
        id,
        app_id,
        email,
        username,
        status,
        created_at,
        updated_at,
        logs
      FROM authx_app_users
      WHERE app_id = ?
      ORDER BY created_at DESC
    `;
    
    try {
      const users = await query(sql, [appId]);
      return users.map(user => ({
        ...user,
        logs: JSON.parse(user.logs || '{"ips":[],"activities":[]}')
      }));
    } catch (error) {
      console.error('Database Error:', error);
      throw new Error('Failed to fetch users');
    }
  }
};
