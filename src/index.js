'use strict';

// Programmatic API: const { detectProjects, scanProjects } = require('vulnsight-ai');

const { detectProjects, loadProject } = require('./detect');
const { scanProjects } = require('./scanner');
const { createClient } = require('./osv');
const { renderText, renderJson } = require('./report');
const { createFinding, dedupeFindings } = require('./findings');
const { scanTarget, createScaAdapter, createSemgrepAdapter, createGitleaksAdapter, runAdapter, execTool } = require('./adapters');

module.exports = {
  detectProjects, loadProject, scanProjects, createClient, renderText, renderJson,
  createFinding, dedupeFindings, scanTarget, createScaAdapter, createSemgrepAdapter, createGitleaksAdapter, runAdapter, execTool,
};
