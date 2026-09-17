/**
 * Patch Generator — Generates framework-tailored code patches for security and QA findings.
 * Supports Next.js, Express, FastAPI, and Django.
 */

export function generateAutoPatch(finding) {
    const title = (finding.title || '').toLowerCase();
    const desc = (finding.description || '').toLowerCase();
    const owasp = (finding.owasp?.id || finding.owasp || '').toLowerCase();

    // 1. Content Security Policy (CSP) / Missing Security Headers
    if (title.includes('content-security-policy') || title.includes('csp') || title.includes('header') || desc.includes('content-security-policy')) {
        return {
            category: 'Security Headers & CSP',
            recommendation: 'Configure strict Content-Security-Policy, HSTS, X-Content-Type-Options, and X-Frame-Options headers.',
            frameworks: {
                'Next.js (middleware.ts)': {
                    file: 'middleware.ts (Root Directory)',
                    code: `// middleware.ts - Next.js Security Headers
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const response = NextResponse.next();

  // Strict Content-Security-Policy & Hardening Headers
  response.headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none';"
  );
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  return response;
}`
                },
                'Node.js / Express': {
                    file: 'app.js / server.js',
                    code: `// Express Security Middleware with Helmet
import express from 'express';
import helmet from 'helmet';

const app = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  })
);`
                },
                'FastAPI / Python': {
                    file: 'main.py',
                    code: `# FastAPI Security Headers Middleware
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; frame-ancestors 'none';"
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

app.add_middleware(SecurityHeadersMiddleware)`
                },
                'Django / Python': {
                    file: 'settings.py',
                    code: `# Django settings.py Security Configuration
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True

# Add django-csp to INSTALLED_APPS and configure:
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)`
                }
            }
        };
    }

    // 2. CORS Misconfiguration / Arbitrary Origin Reflection
    if (title.includes('cors') || desc.includes('cors') || desc.includes('access-control-allow-origin')) {
        return {
            category: 'CORS Configuration & Access Control',
            recommendation: 'Replace wildcard or reflected origins with an explicit, secure domain whitelist.',
            frameworks: {
                'Next.js (next.config.js)': {
                    file: 'next.config.js or middleware.ts',
                    code: `// next.config.js - Explicit Allowed CORS Headers
module.exports = {
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: process.env.ALLOWED_ORIGIN || 'https://your-domain.com' },
          { key: 'Access-Control-Allow-Methods', value: 'GET,POST,PUT,DELETE,OPTIONS' },
          { key: 'Access-Control-Allow-Headers', value: 'Content-Type, Authorization' },
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      },
    ];
  },
};`
                },
                'Node.js / Express': {
                    file: 'app.js',
                    code: `// Express CORS Whitelist Middleware
import cors from 'cors';

const allowedOrigins = [
  'https://your-app.com',
  'https://staging.your-app.com',
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl) or in whitelist
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Blocked by CORS policy'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);`
                },
                'FastAPI / Python': {
                    file: 'main.py',
                    code: `# FastAPI CORS Middleware with Whitelist
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI()

origins = [
    "https://your-app.com",
    os.getenv("FRONTEND_URL", "http://localhost:3000"),
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Explicit whitelist (avoid ["*"])
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)`
                },
                'Django / Python': {
                    file: 'settings.py',
                    code: `# Django settings.py (using django-cors-headers)
CORS_ALLOW_ALL_ORIGINS = False  # NEVER True in production

CORS_ALLOWED_ORIGINS = [
    "https://your-app.com",
    "https://api.your-app.com",
]
CORS_ALLOW_CREDENTIALS = True`
                }
            }
        };
    }

    // 3. XSS / Dangerous HTML Injection
    if (title.includes('xss') || desc.includes('xss') || desc.includes('script') || owasp.includes('a03')) {
        return {
            category: 'Cross-Site Scripting (XSS) Prevention',
            recommendation: 'Sanitize user-controlled HTML with DOMPurify and avoid dangerous raw innerHTML rendering.',
            frameworks: {
                'Next.js / React': {
                    file: 'components/SafeRender.tsx',
                    code: `// React / Next.js Component Safe HTML Sanitizer
import DOMPurify from 'isomorphic-dompurify';

interface SafeHTMLProps {
  content: string;
}

export function SafeHTML({ content }: SafeHTMLProps) {
  // Sanitize all dynamic content before rendering
  const cleanHTML = DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'li', 'code'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
  });

  return <div dangerouslySetInnerHTML={{ __html: cleanHTML }} />;
}`
                },
                'Node.js / Express': {
                    file: 'utils/sanitize.js',
                    code: `// Express Input Sanitizer Utility
import sanitizeHtml from 'sanitize-html';

export function sanitizeInput(dirtyText) {
  return sanitizeHtml(dirtyText, {
    allowedTags: ['b', 'i', 'em', 'strong', 'a'],
    allowedAttributes: {
      a: ['href']
    },
    transformTags: {
      a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer' })
    }
  });
}`
                },
                'FastAPI / Python': {
                    file: 'utils/sanitizer.py',
                    code: `# Python Bleach HTML Sanitizer
import bleach

ALLOWED_TAGS = ['a', 'abbr', 'b', 'code', 'em', 'i', 'strong']
ALLOWED_ATTRIBUTES = {'a': ['href', 'title', 'rel']}

def sanitize_user_input(dirty_html: str) -> str:
    return bleach.clean(
        dirty_html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True
    )`
                },
                'Django / Python': {
                    file: 'templates/example.html',
                    code: `{# Django Template Safe Escaping #}
{# Django auto-escapes variables by default #}
{{ user_comment }}

{# If rendering Markdown or formatted text, sanitize explicitly with bleach: #}
{{ user_comment|safe }} {# ONLY use |safe AFTER bleach cleaning in view #}`
                }
            }
        };
    }

    // 4. SQL Injection
    if (title.includes('sql') || desc.includes('sql') || desc.includes('sqli')) {
        return {
            category: 'SQL Injection Prevention',
            recommendation: 'Replace dynamic raw SQL concatenation with parameterized queries or an ORM.',
            frameworks: {
                'Node.js / Prisma': {
                    file: 'services/db.js',
                    code: `// Parameterized Query with Prisma / pg
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

// SAFE: Use Prisma built-in parameterized queries
export async function getUser(username) {
  return await prisma.user.findUnique({
    where: { username },
  });
}`
                },
                'Node.js / PostgreSQL': {
                    file: 'db/query.js',
                    code: `// Parameterized Query with pg library
import { pool } from './pool.js';

export async function findUserById(userId) {
  // SAFE: Parameters passed as $1 array, never concatenated!
  const query = 'SELECT id, email, created_at FROM users WHERE id = $1';
  const result = await pool.query(query, [userId]);
  return result.rows[0];
}`
                },
                'FastAPI / SQLAlchemy': {
                    file: 'crud/user.py',
                    code: `# SQLAlchemy Parameterized ORM Query
from sqlalchemy.orm import Session
from models import User

def get_user_by_email(db: Session, email: str):
    # SAFE: SQLAlchemy parameterizes the input automatically
    return db.query(User).filter(User.email == email).first()`
                },
                'Django / Python': {
                    file: 'views.py',
                    code: `# Django ORM Parameterized Query
from .models import UserAccount

def get_profile(request, username):
    # SAFE: Django ORM uses parameterized queries under the hood
    account = UserAccount.objects.filter(username=username).first()
    return account`
                }
            }
        };
    }

    // 5. Default Fallback
    return {
        category: 'Input Validation & Defensive Guardrails',
        recommendation: finding.remediation || 'Apply strict schema validation on all inputs and enforce least-privilege security policies.',
        frameworks: {
            'Next.js (Zod Schema)': {
                file: 'lib/validation.ts',
                code: `// Next.js API Route Input Validation with Zod
import { z } from 'zod';

export const RequestSchema = z.object({
  id: z.string().uuid(),
  input: z.string().min(1).max(500).trim(),
  role: z.enum(['user', 'admin']).default('user'),
});

export function validatePayload(data: unknown) {
  return RequestSchema.safeParse(data);
}`
            },
            'Node.js / Express': {
                file: 'middleware/validate.js',
                code: `// Express Input Validation Middleware
import { body, validationResult } from 'express-validator';

export const validateRequest = [
  body('email').isEmail().normalizeEmail(),
  body('input').trim().isLength({ min: 1, max: 500 }),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];`
            },
            'FastAPI / Pydantic': {
                file: 'schemas/request.py',
                code: `# FastAPI Pydantic Schema Validation
from pydantic import BaseModel, Field, EmailStr

class SecureRequestSchema(BaseModel):
    email: EmailStr
    query: str = Field(..., min_length=1, max_length=500)
    
    class Config:
        anystr_strip_whitespace = True`
            },
            'Django / Python': {
                file: 'forms.py',
                code: `# Django Form Clean & Validation
from django import forms

class SecureInputForm(forms.Form):
    email = forms.EmailField()
    query = forms.CharField(min_length=1, max_length=500)

    def clean_query(self):
        data = self.cleaned_data['query']
        return data.strip()`
            }
        }
    };
}
