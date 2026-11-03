'use strict';

// Programmatic API: const { detectProjects, scanProjects } = require('vulnsight-ai');

const { detectProjects, loadProject } = require('./detect');
const { scanProjects } = require('./scanner');
const { createClient } = require('./osv');
const { renderText, renderJson } = require('./report');

module.exports = { detectProjects, loadProject, scanProjects, createClient, renderText, renderJson };
