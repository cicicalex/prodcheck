/**
 * Stock express-rate-limit setup. No key generator: the identity is req.ip,
 * which Express derives itself.
 */
const rateLimit = require('express-rate-limit');

module.exports = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});
