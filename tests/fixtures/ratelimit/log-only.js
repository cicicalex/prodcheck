/**
 * Rate limited with express-rate-limit defaults — the identity is req.ip.
 * The forwarded header is read for a debug log only and never keys anything.
 */
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });

module.exports = function register(app) {
  app.use(limiter);
  app.use((req, res, next) => {
    const forwarded = req.headers['x-forwarded-for'];
    console.log('request via %s', forwarded);
    next();
  });
};
