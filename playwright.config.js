'use strict';

const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './e2e',
  timeout: 240_000,
  // The pipeline run is stateful (one server, one shared SQLite db) — keep
  // the e2e suite serial.
  workers: 1,
  fullyParallel: false,
  use: {
    baseURL: 'http://localhost:3911',
  },
  reporter: [['list']],
});
