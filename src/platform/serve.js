'use strict';

// Container entry point: configuration comes from the environment.
const { startPlatform } = require('./app');

startPlatform({
  port: Number(process.env.PORT || 4400),
  host: process.env.HOST || '0.0.0.0',
  dataDir: process.env.VULNSIGHT_DATA || '/data',
}).then((app) => {
  console.log(JSON.stringify({ msg: 'VulnSight AI started', port: app.port }));
  const shutdown = () => app.stop().then(() => process.exit(0));
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}).catch((err) => {
  console.error(JSON.stringify({ level: 'fatal', message: err.message }));
  process.exit(1);
});
