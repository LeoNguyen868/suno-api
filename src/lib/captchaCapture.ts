/**
 * Standalone CAPTCHA capture logic extracted from SunoApi.
 * Used for testing with visible browser and by SunoApi.getCaptcha().
 */

import pino from 'pino';
import yn from 'yn';
import { isPage, sleep } from '@/lib/utils';
import { Solver } from '@2captcha/captcha-solver';
import type { paramsCoordinates } from '@2captcha/captcha-solver/dist/structs/2captcha';
import {
  BrowserContext,
  Page,
  Locator,
  chromium,
  firefox
} from 'rebrowser-playwright-core';
import { createCursor, Cursor } from 'ghost-cursor-playwright';
import { promises as fs } from 'fs';
import path from 'node:path';

const TIMEOUTS = {
  PAGE_NAVIGATION: Number(process.env.TIMEOUT_PAGE_NAVIGATION) || 0,
  PAGE_API_RESPONSE: Number(process.env.TIMEOUT_PAGE_API_RESPONSE) || 30000,
  POPUP_CLOSE: Number(process.env.TIMEOUT_POPUP_CLOSE) || 2000,
  TEXTAREA_WAIT: Number(process.env.TIMEOUT_TEXTAREA_WAIT) || 3000,
  CREATE_BUTTON_WAIT: Number(process.env.TIMEOUT_CREATE_BUTTON_WAIT) || 5000,
  CAPTCHA_SCREENSHOT: Number(process.env.TIMEOUT_CAPTCHA_SCREENSHOT) || 5000,
  CAPTCHA_IMAGE_LOAD_DELAY: Number(process.env.TIMEOUT_CAPTCHA_IMAGE_LOAD) || 3,
  CAPTCHA_PIECE_UNLOCK_DELAY:
    Number(process.env.TIMEOUT_CAPTCHA_PIECE_UNLOCK) || 1.1
} as const;

interface CaptchaCoordinate {
  x: number;
  y: number;
}

interface CaptchaSolution {
  id: string;
  data: CaptchaCoordinate[];
}

interface BoundingBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

function toError(error: unknown): Error {
  if (error instanceof Error) return error;
  if (typeof error === 'string') return new Error(error);
  if (error && typeof error === 'object' && 'message' in error)
    return new Error(String((error as { message: unknown }).message));
  return new Error('Unknown error occurred');
}

function sanitize(data: unknown): unknown {
  if (!data) return data;
  if (typeof data === 'string')
    return data.replace(
      /([a-zA-Z0-9_-]{20,})/g,
      (m) => `${m.substring(0, 8)}...`
    );
  if (typeof data === 'object') {
    const out: Record<string, unknown> = Array.isArray(data) ? [] : {};
    for (const key in data as Record<string, unknown>) {
      const lower = key.toLowerCase();
      if (
        lower.includes('cookie') ||
        lower.includes('token') ||
        lower.includes('authorization') ||
        lower.includes('auth') ||
        lower.includes('key') ||
        lower.includes('secret')
      ) {
        const v = String((data as Record<string, unknown>)[key]);
        out[key] =
          v.length > 8 ? `${v.substring(0, 8)}...[REDACTED]` : '[REDACTED]';
      } else {
        out[key] = sanitize((data as Record<string, unknown>)[key]);
      }
    }
    return out;
  }
  return data;
}

export interface CaptchaCaptureOptions {
  cookies: Record<string, string | undefined>;
  userAgent?: string;
  headless?: boolean;
  verbose?: boolean;
  ghostCursor?: boolean;
  twoCaptchaKey: string;
  onAuthToken?: (token: string) => void;
}

function getBrowserType() {
  const b = process.env.BROWSER?.toLowerCase();
  return b === 'firefox' ? firefox : chromium;
}

async function launchBrowserContext(
  options: CaptchaCaptureOptions,
  log: pino.Logger
): Promise<BrowserContext> {
  const args = [
    '--disable-blink-features=AutomationControlled',
    '--disable-web-security',
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-features=site-per-process',
    '--disable-features=IsolateOrigins',
    '--disable-extensions',
    '--disable-infobars'
  ];
  if (yn(process.env.BROWSER_DISABLE_GPU, { default: false }))
    args.push(
      '--enable-unsafe-swiftshader',
      '--disable-gpu',
      '--disable-setuid-sandbox'
    );
  if (!options.headless) args.push('--auto-open-devtools-for-tabs');

  const browser = await getBrowserType().launch({
    args,
    headless: options.headless ?? true
  });
  const context = await browser.newContext({
    userAgent: options.userAgent,
    locale: process.env.BROWSER_LOCALE,
    viewport: null
  });

  const lax = 'Lax' as const;
  const none = 'None' as const;
  const cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    sameSite: 'Lax' | 'Strict' | 'None';
    secure?: boolean;
    httpOnly?: boolean;
  }> = [];

  for (const key in options.cookies) {
    if (key === '__client' || key === '__client_uat') continue;
    cookies.push({
      name: key,
      value: `${options.cookies[key]}`,
      domain: '.suno.com',
      path: '/',
      sameSite: lax
    });
  }

  if (options.cookies.__client) {
    cookies.push({
      name: '__client',
      value: `${options.cookies.__client}`,
      domain: 'auth.suno.com',
      path: '/',
      sameSite: none,
      secure: true,
      httpOnly: true
    });
    cookies.push({
      name: '__client',
      value: `${options.cookies.__client}`,
      domain: 'clerk.suno.com',
      path: '/',
      sameSite: lax,
      secure: true,
      httpOnly: true
    });
  }

  let clientUatTimestamp = options.cookies.__client_uat || '0';
  for (const key in options.cookies) {
    if (
      key.startsWith('__client_uat_') &&
      options.cookies[key] &&
      options.cookies[key] !== '0'
    ) {
      clientUatTimestamp = options.cookies[key]!;
      log.debug(`Found session-variant UAT: ${key}`);
      break;
    }
  }

  if (clientUatTimestamp && clientUatTimestamp !== '0') {
    cookies.push({
      name: '__client_uat',
      value: '0',
      domain: 'auth.suno.com',
      path: '/',
      sameSite: none,
      secure: true
    });
    cookies.push({
      name: '__client_uat',
      value: clientUatTimestamp,
      domain: '.suno.com',
      path: '/',
      sameSite: lax,
      secure: true
    });
  } else {
    log.warn('No valid __client_uat timestamp found');
  }

  await context.addCookies(cookies);
  return context;
}

export async function captureCaptchaToken(
  options: CaptchaCaptureOptions
): Promise<string | null> {
  const log = pino(options.verbose ? { level: 'debug' } : {});
  const solver = new Solver(options.twoCaptchaKey);

  const context = await launchBrowserContext(options, log);
  const page = await context.newPage();

  log.info(
    'Step 1: Navigating to suno.com homepage to establish Clerk session...'
  );
  await page.goto('https://suno.com', {
    referer: 'https://www.google.com/',
    waitUntil: 'domcontentloaded',
    timeout: TIMEOUTS.PAGE_NAVIGATION || undefined
  });

  log.info('Waiting for Clerk JS to establish session...');
  try {
    await page.waitForResponse(
      (r) => r.url().includes('auth.suno.com/v1/client') && r.status() === 200,
      { timeout: 10000 }
    );
    log.info('Clerk authentication response received');
    await sleep(2);
  } catch (e) {
    log.warn('Clerk auth response timeout - continuing anyway');
  }

  log.info('Step 2: Navigating to suno.com/create...');
  await page.goto('https://suno.com/create', {
    referer: 'https://suno.com/',
    waitUntil: 'domcontentloaded',
    timeout: TIMEOUTS.PAGE_NAVIGATION || undefined
  });

  log.info('Waiting for page to fully load...');
  try {
    await page.waitForResponse(
      (r) => r.url().includes('/api/project/') && r.status() === 200,
      { timeout: TIMEOUTS.PAGE_API_RESPONSE }
    );
    log.info('Page fully loaded');
  } catch {
    log.info('API response timeout - continuing anyway');
  }

  let cursor: Cursor | undefined;
  if (options.ghostCursor) cursor = await createCursor(page);

  log.info('Triggering the CAPTCHA');

  try {
    await page.getByLabel('Close').click({ timeout: TIMEOUTS.POPUP_CLOSE });
    log.info('Popup closed successfully');
  } catch {
    try {
      await page.locator('button[aria-label="Close"]').click({
        timeout: TIMEOUTS.POPUP_CLOSE
      });
      log.info('Popup closed with aria-label');
    } catch {
      try {
        await page.locator('svg[data-testid="close-icon"]').click({
          timeout: TIMEOUTS.POPUP_CLOSE
        });
        log.info('Popup closed with SVG selector');
      } catch {
        log.info('No popup found - continuing');
      }
    }
  }

  page.on('request', (req) => {
    if (req.url().includes('/api/'))
      log.info(`API Request: ${req.method()} ${req.url()}`);
  });

  const tokenPromise = new Promise<string | null>((resolve, reject) => {
    const patterns = [
      '**/api/generate/v2/**',
      '**/api/generate/v3/**',
      '**/api/generate/**',
      '**/generate/**'
    ];
    patterns.forEach((pattern) => {
      page.route(pattern, async (route) => {
        try {
          log.info(
            `Route intercepted! Pattern: ${pattern}, URL: ${route.request().url()}`
          );
          const request = route.request();
          const headers = request.headers();
          const postData = request.postDataJSON() as {
            token?: string;
            hcaptcha_token?: string;
          } | null;
          log.debug('Request headers', sanitize(headers));
          log.debug('Request post data', sanitize(postData));
          const token = postData?.token || postData?.hcaptcha_token;
          if (headers.authorization && options.onAuthToken) {
            const authToken = headers.authorization.split('Bearer ').pop();
            if (authToken) options.onAuthToken(authToken);
          }
          log.info(`Captured token: ${token ? 'Yes' : 'No'}`);
          log.info('Aborting request and closing browser');
          route.abort();
          const browserInstance = context.browser();
          if (browserInstance)
            browserInstance
              .close()
              .catch((e) =>
                log.error({ err: toError(e) }, 'Failed to close browser')
              );
          resolve(token || null);
        } catch (err) {
          reject(toError(err));
        }
      });
    });
  });

  log.info('Looking for song description textarea...');
  let textarea: Locator;
  try {
    textarea = page.locator('textarea[placeholder*="Hip-hop"]');
    await textarea.waitFor({
      state: 'visible',
      timeout: TIMEOUTS.TEXTAREA_WAIT
    });
    log.info('Found textarea with Hip-hop placeholder');
  } catch {
    const textareas = page.locator('textarea');
    const count = await textareas.count();
    log.info(`Found ${count} textareas on page`);
    let found: Locator | null = null;
    for (let i = 0; i < count; i++) {
      const ta = textareas.nth(i);
      if (await ta.isVisible()) {
        found = ta;
        log.info(`Using textarea at index ${i}`);
        break;
      }
    }
    if (!found) throw new Error('Could not find any visible textarea');
    textarea = found;
  }

  const testPrompt = process.env.CAPTCHA_TEST_PROMPT || 'Lorem ipsum';
  log.info('Filling textarea with test prompt...');
  await textarea.focus();
  await textarea.fill(testPrompt);
  log.info('Textarea filled successfully');

  log.info('Looking for Create button...');
  const button = page.locator('button[aria-label="Create song"]');
  await button.waitFor({
    state: 'visible',
    timeout: TIMEOUTS.CREATE_BUTTON_WAIT
  });
  log.info('Clicking Create button...');
  await button.click();
  log.info('Create button clicked - waiting for CAPTCHA...');

  async function click(
    target: Locator | Page,
    position?: { x: number; y: number }
  ): Promise<void> {
    if (cursor) {
      let pos: BoundingBox | { x: number; y: number } = isPage(target)
        ? { x: 0, y: 0 }
        : ((await (target as Locator).boundingBox()) as BoundingBox);
      if (position) {
        const base = 'width' in pos ? pos : { ...pos, width: 0, height: 0 };
        pos = {
          x: base.x + position.x,
          y: base.y + position.y,
          width: base.width,
          height: base.height
        };
      }
      return cursor.actions.click({ target: pos });
    }
    if (isPage(target))
      return (target as Page).mouse.click(position?.x ?? 0, position?.y ?? 0);
    (target as Locator).click({ force: true, position });
  }

  async function solveCaptchaWithRetry(
    challenge: Locator,
    isDrag: boolean
  ): Promise<CaptchaSolution | null> {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        log.info('Sending the CAPTCHA to 2Captcha');
        const payload: paramsCoordinates = {
          body: (
            await challenge.screenshot({ timeout: TIMEOUTS.CAPTCHA_SCREENSHOT })
          ).toString('base64'),
          lang: process.env.BROWSER_LOCALE
        };
        if (isDrag) {
          payload.textinstructions =
            'CLICK on the shapes at their edge or center as shown above—please be precise!';
          const instructionsPath = path.join(
            process.cwd(),
            'public',
            'drag-instructions.jpg'
          );
          try {
            payload.imginstructions = (
              await fs.readFile(instructionsPath)
            ).toString('base64');
          } catch {
            log.warn('drag-instructions.jpg not found, proceeding without');
          }
        }
        return (await solver.coordinates(
          payload
        )) as unknown as CaptchaSolution;
      } catch (err) {
        log.info(toError(err).message);
        if (attempt < 2) log.info('Retrying...');
        else throw err;
      }
    }
    return null;
  }

  function validateDragSolution(solution: CaptchaSolution): boolean {
    if (solution.data.length % 2 !== 0) {
      log.info('Solution has odd points, requesting new...');
      solver.badReport(solution.id);
      return false;
    }
    return true;
  }

  async function performDragInteraction(
    p: Page,
    box: BoundingBox,
    solution: CaptchaSolution
  ): Promise<void> {
    for (let i = 0; i < solution.data.length; i += 2) {
      const start = solution.data[i];
      const end = solution.data[i + 1];
      await p.mouse.move(box.x + +start.x, box.y + +start.y);
      await p.mouse.down();
      await sleep(TIMEOUTS.CAPTCHA_PIECE_UNLOCK_DELAY);
      await p.mouse.move(box.x + +end.x, box.y + +end.y, { steps: 30 });
      await p.mouse.up();
    }
  }

  async function performClickInteraction(
    ch: Locator,
    solution: CaptchaSolution
  ): Promise<void> {
    for (const coord of solution.data)
      await click(ch, { x: +coord.x, y: +coord.y });
  }

  async function submitCaptchaSolution(
    frame: ReturnType<Page['frameLocator']>,
    btn: Locator
  ): Promise<void> {
    try {
      await click(frame.locator('.button-submit'));
    } catch (e) {
      const err = toError(e);
      if (err.message.includes('viewport')) await click(btn);
      else throw err;
    }
  }

  const captchaSolvingPromise = new Promise<void>(async (resolve, reject) => {
    const frame = page.frameLocator('iframe[title*="hCaptcha"]');
    const challenge = frame.locator('.challenge-container');
    try {
      let shouldWaitForImages = true;
      while (true) {
        if (shouldWaitForImages) await sleep(TIMEOUTS.CAPTCHA_IMAGE_LOAD_DELAY);
        const promptText = await challenge
          .locator('.prompt-text')
          .first()
          .innerText();
        const isDragType = promptText.toLowerCase().includes('drag');
        const solution = await solveCaptchaWithRetry(challenge, isDragType);
        if (!solution)
          throw new Error('Failed to solve CAPTCHA after 3 attempts');
        if (isDragType) {
          if (!validateDragSolution(solution)) {
            shouldWaitForImages = false;
            continue;
          }
          const box = await challenge.boundingBox();
          if (!box) throw new Error('.challenge-container boundingBox is null');
          await performDragInteraction(page, box, solution);
          shouldWaitForImages = true;
        } else {
          await performClickInteraction(challenge, solution);
        }
        await submitCaptchaSolution(frame, button);
      }
    } catch (e) {
      const err = toError(e);
      if (err.message.includes('been closed') || err.message === 'AbortError')
        resolve();
      else reject(err);
    }
  }).catch((e) => {
    const err = toError(e);
    const browserInstance = context.browser();
    if (browserInstance) browserInstance.close().catch(() => {});
    throw err;
  });

  await Promise.race([tokenPromise, captchaSolvingPromise]);
  return tokenPromise;
}
