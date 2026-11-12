'use strict';

const { urlHash } = require('./scope');

function emptyInventory(engine) {
  return {
    engine,
    pages: [],
    endpoints: [],
    forms: [],
    links: [],
    scripts: [],
    findings: [],
    stopped: false,
  };
}

function pushPage(inventory, parsed, extra) {
  const href = parsed.href;
  const hash = urlHash(href);
  let page = inventory.pages.find((p) => p.urlHash === hash);
  if (!page) {
    page = {
      url: href,
      urlHash: hash,
      path: parsed.pathname,
      statusCode: extra.statusCode || 0,
      contentType: extra.contentType || '',
      depth: extra.depth || 0,
      title: extra.title || '',
    };
    inventory.pages.push(page);
  }
  return page;
}

function pushEndpoint(inventory, parsed, extra) {
  const paramNames = [...parsed.searchParams.keys()];
  inventory.endpoints.push({
    url: parsed.href,
    path: parsed.pathname,
    method: extra.method,
    statusCode: extra.statusCode,
    contentType: extra.contentType,
    paramNames,
  });
}

module.exports = { emptyInventory, pushPage, pushEndpoint };
