'use strict';

const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');

const DEFAULT_PORTS = '443,2053,2083,2087,2096,8443';
const MAX_RESPONSE_BYTES = 128 * 1024;

const blockedIpv4Addresses = new net.BlockList();
[
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4]
].forEach(([network, prefix]) => blockedIpv4Addresses.addSubnet(network, prefix, 'ipv4'));

const blockedIpv6Addresses = new net.BlockList();
[
  ['::', 128],
  ['::1', 128],
  ['::ffff:0:0', 96],
  ['100::', 64],
  ['2001:db8::', 32],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8]
].forEach(([network, prefix]) => blockedIpv6Addresses.addSubnet(network, prefix, 'ipv6'));

function parseAllowedPorts(value = DEFAULT_PORTS) {
  const ports = String(value)
    .split(',')
    .map((part) => Number(part.trim()))
    .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);
  return new Set(ports.length ? ports : DEFAULT_PORTS.split(',').map(Number));
}

function isPublicIPAddress(address) {
  const value = String(address || '').trim();
  const family = net.isIP(value);
  if (!family) return false;
  return family === 4
    ? !blockedIpv4Addresses.check(value, 'ipv4')
    : !blockedIpv6Addresses.check(value, 'ipv6');
}

function isValidHostname(hostname) {
  const value = String(hostname || '').trim().toLowerCase();
  if (!value || value.length > 253 || net.isIP(value)) return false;
  return value.split('.').every((label) => (
    label.length >= 1 &&
    label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  ));
}

function secureEqual(actual, expected) {
  const actualBuffer = Buffer.from(String(actual || ''));
  const expectedBuffer = Buffer.from(String(expected || ''));
  return actualBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function sendJson(response, status, data) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(JSON.stringify(data));
}

function probeCandidate({ ip, port, sni, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    let responseBytes = 0;
    const chunks = [];
    const request = https.request({
      hostname: ip,
      port,
      servername: sni,
      method: 'GET',
      path: '/ip.json',
      headers: {
        Host: sni,
        Accept: 'application/json',
        Connection: 'close',
        'User-Agent': 'BestCF-ARM-Probe/1.0'
      },
      ALPNProtocols: ['http/1.1'],
      rejectUnauthorized: false,
      agent: false
    }, (targetResponse) => {
      targetResponse.on('data', (chunk) => {
        responseBytes += chunk.length;
        if (responseBytes > MAX_RESPONSE_BYTES) {
          request.destroy(new Error('target response is too large'));
          return;
        }
        chunks.push(chunk);
      });
      targetResponse.on('end', () => {
        if (targetResponse.statusCode < 200 || targetResponse.statusCode >= 300) {
          reject(new Error(`target HTTP ${targetResponse.statusCode || 0}`));
          return;
        }
        let data;
        try {
          data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch {
          reject(new Error('target response is not JSON'));
          return;
        }
        resolve({
          ...data,
          probeIp: ip,
          probePort: port,
          probeLatency: Math.max(1, Date.now() - started),
          probeSource: 'arm-relay'
        });
      });
    });

    request.setTimeout(timeoutMs, () => request.destroy(new Error('target probe timed out')));
    request.on('error', reject);
    request.end();
  });
}

function createProbeServer(options = {}) {
  const token = String(options.token || process.env.PROBE_TOKEN || '').trim();
  const defaultSni = String(options.sni || process.env.PROBE_SNI || 'eee21.albb.ccwu.cc').trim().toLowerCase();
  const allowedPorts = parseAllowedPorts(options.allowedPorts || process.env.PROBE_ALLOWED_PORTS);
  const defaultTimeoutMs = Math.min(10000, Math.max(500, Number(options.timeoutMs || process.env.PROBE_TIMEOUT_MS) || 3000));

  if (!token) throw new Error('PROBE_TOKEN is required');
  if (!isValidHostname(defaultSni)) throw new Error('PROBE_SNI must be a valid hostname');

  return http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url, 'http://probe-agent.local');
    if (requestUrl.pathname === '/health') {
      sendJson(response, 200, { ok: true, service: 'edgetunnel-probe-agent' });
      return;
    }
    if (requestUrl.pathname !== '/probe') {
      sendJson(response, 404, { error: 'not found' });
      return;
    }
    if (request.method !== 'GET') {
      sendJson(response, 405, { error: 'method not allowed' });
      return;
    }

    const authorization = String(request.headers.authorization || '');
    if (!authorization.startsWith('Bearer ') || !secureEqual(authorization.slice(7), token)) {
      sendJson(response, 401, { error: 'unauthorized' });
      return;
    }

    const ip = String(requestUrl.searchParams.get('ip') || '').trim();
    const port = Number(requestUrl.searchParams.get('port') || 0);
    const sni = String(requestUrl.searchParams.get('sni') || defaultSni).trim().toLowerCase();
    const timeoutMs = Math.min(10000, Math.max(500, Number(requestUrl.searchParams.get('timeout')) || defaultTimeoutMs));
    if (!isPublicIPAddress(ip)) {
      sendJson(response, 400, { error: 'invalid public IP' });
      return;
    }
    if (!allowedPorts.has(port)) {
      sendJson(response, 400, { error: 'unsupported TLS port' });
      return;
    }
    if (!isValidHostname(sni)) {
      sendJson(response, 400, { error: 'invalid SNI hostname' });
      return;
    }

    try {
      const result = await probeCandidate({ ip, port, sni, timeoutMs });
      sendJson(response, 200, result);
    } catch (error) {
      sendJson(response, 502, { error: error?.message || 'probe failed' });
    }
  });
}

function startServer() {
  const host = process.env.PROBE_LISTEN_HOST || '127.0.0.1';
  const port = Number(process.env.PROBE_LISTEN_PORT) || 8788;
  const server = createProbeServer();
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.listen(port, host, () => {
    process.stdout.write(`probe agent listening on http://${host}:${port}\n`);
  });
  const close = () => server.close(() => process.exit(0));
  process.on('SIGINT', close);
  process.on('SIGTERM', close);
}

if (require.main === module) startServer();

module.exports = {
  createProbeServer,
  isPublicIPAddress,
  isValidHostname,
  parseAllowedPorts,
  probeCandidate
};
