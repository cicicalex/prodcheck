/**
 * Same login limiter, but the app declares its proxy chain. With trust proxy
 * set, Express resolves the client address from validated hops only.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const limiter = new RateLimiterMemory({ points: 10, duration: 60 });

module.exports = function register(app) {
  app.set('trust proxy', 1);
  app.post('/api/login', async (req, res, next) => {
    const ip = req.headers['x-forwarded-for'].split(',')[0].trim();
    await limiter.consume(ip);
    next();
  });
};
