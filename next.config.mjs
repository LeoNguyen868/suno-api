/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack: (config, { isServer }) => {
    config.module.rules.push({
      test: /\.(ttf|html)$/i,
      type: 'asset/resource'
    });
    if (isServer) {
      config.externals = config.externals || [];
      config.externals.push({
        'rebrowser-playwright-core': 'commonjs rebrowser-playwright-core',
        'playwright-core': 'commonjs rebrowser-playwright-core',
        'tree-sitter': 'commonjs tree-sitter',
        'tree-sitter-json': 'commonjs tree-sitter-json',
        'tree-sitter-yaml': 'commonjs tree-sitter-yaml',
        'web-tree-sitter': 'commonjs web-tree-sitter',
        'bufferutil': 'commonjs bufferutil',
        'utf-8-validate': 'commonjs utf-8-validate',
        'electron': 'commonjs electron',
        'pino': 'commonjs pino',
        'pino-pretty': 'commonjs pino-pretty',
      });
    }
    return config;
  },
  experimental: {
    serverMinification: false,
    serverComponentsExternalPackages: [
      'rebrowser-playwright-core',
      'playwright-core',
      '@playwright/browser-chromium',
      'tree-sitter',
      'tree-sitter-json',
      'tree-sitter-yaml',
      'web-tree-sitter',
      'bufferutil',
      'utf-8-validate',
      'electron',
      'pino',
      'pino-pretty',
      '@2captcha/captcha-solver',
      'ghost-cursor-playwright',
    ],
  },
};

export default nextConfig;
