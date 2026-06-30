const pino = require('pino');

const NODE_ENV = process.env.NODE_ENV || 'development';
const isProd = NODE_ENV === 'production';

const logger = pino({
  level: process.env.LOG_LEVEL || (isProd ? 'info' : 'debug'),
  transport: isProd
    ? undefined
    : { target: 'pino/file', options: { destination: 1 } },
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'body.password',
      'body.currentPassword',
      'body.newPassword',
      'body.token',
      '*.newPw',
      '*.oldPassword',
      '*.current',
      '*.newPassword',
      '*.confirmPassword',
    ],
    censor: '[REDACTED]',
  },
  serializers: {
    req: (r) => ({
      method: r.method,
      url: r.url,
      query: r.query,
    }),
    res: (r) => ({
      statusCode: r.statusCode,
    }),
    err: pino.stdSerializers.err,
  },
});

module.exports = logger;
