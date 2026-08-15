/**
 * Login endpoint, brute-force protected by rate-limiter-flexible.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const limiter = new RateLimiterMemory({ points: 10, duration: 60 });

module.exports = function register(app) {
  app.post('/api/login', async (req, res, next) => {
    const ip = req.headers['x-forwarded-for'].split(',')[0].trim();
    await limiter.consume(ip);
    next();
  });
};
