/**
 * Standalone CAPTCHA capture test script.
 * Runs with visible (non-headless) browser and verbose logging for manual observation.
 *
 * Usage:
 *   cd suno-api && npm run captcha-test
 *
 * Required env: SUNO_COOKIE, TWOCAPTCHA_KEY (set in .env or export)
 * Loads .env from suno-api/ or project root (../)
 */

import path from 'path';
import { config } from 'dotenv';
config({ path: path.join(process.cwd(), '.env') });
config({ path: path.join(process.cwd(), '..', '.env') });
import * as cookie from 'cookie';
import UserAgent from 'user-agents';
import { captureCaptchaToken } from '../src/lib/captchaCapture';

async function main() {
  const sunoCookie = process.env.SUNO_COOKIE;
  const twoCaptchaKey = process.env.TWOCAPTCHA_KEY;

  if (!sunoCookie?.trim()) {
    console.error(
      'Missing SUNO_COOKIE. Set it in .env or export before running.'
    );
    process.exit(1);
  }
  if (!twoCaptchaKey?.trim()) {
    console.error(
      'Missing TWOCAPTCHA_KEY. Set it in .env or export before running.'
    );
    process.exit(1);
  }

  const cookies = cookie.parse(sunoCookie);
  const userAgent = new UserAgent(/Macintosh/).random().toString();

  console.log(
    'Starting CAPTCHA capture test (visible browser, verbose logs)...'
  );
  console.log('Env: BROWSER_HEADLESS=' + process.env.BROWSER_HEADLESS);

  try {
    const token = await captureCaptchaToken({
      cookies,
      userAgent,
      headless: false,
      verbose: true,
      ghostCursor: false,
      twoCaptchaKey
    });

    if (token) {
      console.log(
        'Success. Captured token (redacted):',
        token.substring(0, 20) + '...'
      );
    } else {
      console.log('No token captured (CAPTCHA might not have been required).');
    }
  } catch (err) {
    console.error('CAPTCHA capture failed:', err);
    process.exit(1);
  }
}

main();
