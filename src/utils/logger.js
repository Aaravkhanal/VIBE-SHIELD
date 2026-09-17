import winston from 'winston';
import path from 'path';
import fs from 'fs';

const LOG_DIR = path.join(process.cwd(), 'vibe-shield-reports', 'logs');

// Patterns for secrets that must never reach any transport (file or console).
const SECRET_PATTERNS = [
  /\bsk-[A-Za-z0-9_-]{8,}\b/g,                 // OpenAI-style keys
  /\bsk-ant-[A-Za-z0-9_-]{8,}\b/g,            // Anthropic-style keys
  /(Bearer\s+)[A-Za-z0-9._-]{8,}/gi,          // Authorization: Bearer <token>
  /(x-api-key["']?\s*[:=]\s*["']?)[A-Za-z0-9._-]{8,}/gi, // x-api-key headers
  /((?:api[_-]?key|apikey|token)["']?\s*[:=]\s*["']?)[A-Za-z0-9._-]{8,}/gi,
];

/** Replace any secret-looking substrings with [REDACTED]. */
export function redactSecrets(value) {
  if (value == null) return value;
  let str = typeof value === 'string' ? value : String(value);
  for (const re of SECRET_PATTERNS) {
    str = str.replace(re, (m, prefix) => (prefix ? `${prefix}[REDACTED]` : '[REDACTED]'));
  }
  return str;
}

// Winston format that scrubs secrets from message + meta before transports.
const redactionFormat = winston.format((info) => {
  if (typeof info.message === 'string') {
    info.message = redactSecrets(info.message);
  }
  for (const key of Object.keys(info)) {
    if (key === 'level' || key === 'message' || key === 'timestamp') continue;
    const v = info[key];
    if (typeof v === 'string') info[key] = redactSecrets(v);
  }
  return info;
});

export function createLogger(options = {}) {
  const { verbose = false, logDir = LOG_DIR } = options;

  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  const logger = winston.createLogger({
    level: verbose ? 'debug' : 'info',
    format: winston.format.combine(
      redactionFormat(),
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    defaultMeta: { agent: 'VIBE SHIELD' },
    transports: [
      new winston.transports.File({
        filename: path.join(logDir, 'vibe-shield-error.log'),
        level: 'error',
      }),
      new winston.transports.File({
        filename: path.join(logDir, 'vibe-shield-audit.log'),
      }),
    ],
  });

  if (process.env.NODE_ENV !== 'production') {
    logger.add(
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.printf(({ level, message, timestamp }) => {
            return `${timestamp} [${level}]: ${message}`;
          })
        ),
        silent: !verbose,
      })
    );
  }

  return logger;
}

export default createLogger;
