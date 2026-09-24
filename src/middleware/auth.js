/**
 * JWT + role middleware (NFR4: bcrypt hashes only, tokens expire).
 */
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';

function signToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), email: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Missing bearer token' } });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (e) {
    const message = e.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message } });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Missing bearer token' } });
    if (req.user.role !== role) {
      return res.status(403).json({ error: { code: 'FORBIDDEN', message: `Requires role: ${role}` } });
    }
    return next();
  };
}

module.exports = { signToken, requireAuth, requireRole, JWT_SECRET, JWT_EXPIRES_IN };