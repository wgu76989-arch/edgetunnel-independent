'use strict';

const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');

const DEFAULT_PORTS = '443,2053,2083,2087,2096,8443';
const MAX_RESPONSE_BYTES = 128 * 1024;
const DEFAULT_SPEED_BYTES = 20_000_000;
const MIN_SPEED_BYTES = 64 * 1024;
const MAX_SPEED_BYTES = 25_000_000;

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

function parseSpeedBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes)) return DEFAULT_SPEED_BYTES;
  return Math.min(MAX_SPEED_BYTES, Math.max(MIN_SPEED_BYTES, Math.round(bytes)));
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
    let tcpLatency = null;
    let tlsLatency = null;
    let httpLatency = null;
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
      httpLatency = Math.max(1, Date.now() - started);
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
        const totalLatency = Math.max(1, Date.now() - started);
        resolve({
          ...data,
          probeIp: ip,
          probePort: port,
          probeLatency: tcpLatency || totalLatency,
          probeTcpLatency: tcpLatency || totalLatency,
          probeTlsLatency: tlsLatency || totalLatency,
          probeHttpLatency: httpLatency || totalLatency,
          probeTotalLatency: totalLatency,
          probeSource: 'arm-relay'
        });
      });
    });

    request.on('socket', (socket) => {
      if (socket.connecting) {
        socket.once('connect', () => {
          tcpLatency = Math.max(1, Date.now() - started);
        });
      } else {
        tcpLatency = Math.max(1, Date.now() - started);
      }
      socket.once('secureConnect', () => {
        tlsLatency = Math.max(1, Date.now() - started);
      });
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error('target probe timed out')));
    request.on('error', reject);
    request.end();
  });
}

function measureCandidateSpeed({ ip, port, sni, timeoutMs, bytes, token }) {
  return new Promise((resolve, reject) => {
    const requestedBytes = parseSpeedBytes(bytes);
    const started = Date.now();
    let firstByteAt = 0;
    let receivedBytes = 0;
    let settled = false;
    let request;

    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(overallTimer);
      if (error) {
        reject(error);
        return;
      }
      if (receivedBytes < MIN_SPEED_BYTES) {
        reject(new Error('target speed response is too small'));
        return;
      }
      const durationMs = Math.max(1, Date.now() - (firstByteAt || started));
      resolve({
        probeIp: ip,
        probePort: port,
        speedMbps: Math.max(0.01, (receivedBytes * 8) / durationMs / 1000),
        speedBytes: receivedBytes,
        speedDurationMs: durationMs,
        probeSource: 'arm-relay'
      });
    };

    const overallTimer = setTimeout(() => {
      if (receivedBytes >= MIN_SPEED_BYTES) finish();
      else finish(new Error('target speed test timed out'));
      request?.destroy();
    }, timeoutMs);

    request = https.request({
      hostname: ip,
      port,
      servername: sni,
      method: 'GET',
      path: `/__down?bytes=${requestedBytes}&_t=${Date.now()}`,
      headers: {
        Host: sni,
        Accept: 'application/octet-stream',
        'Accept-Encoding': 'identity',
        Authorization: `Bearer ${token}`,
        Connection: 'close',
        'User-Agent': 'BestCF-ARM-Speed/1.0'
      },
      ALPNProtocols: ['http/1.1'],
      rejectUnauthorized: false,
      agent: false
    }, (targetResponse) => {
      if (targetResponse.statusCode < 200 || targetResponse.statusCode >= 300) {
        targetResponse.resume();
        finish(new Error(`target speed HTTP ${targetResponse.statusCode || 0}`));
        return;
      }
      targetResponse.on('data', (chunk) => {
        if (!firstByteAt) firstByteAt = Date.now();
        receivedBytes += chunk.length;
        if (receivedBytes >= requestedBytes) {
          finish();
          request.destroy();
        }
      });
      targetResponse.on('end', () => finish());
      targetResponse.on('error', (error) => finish(error));
    });

    request.setTimeout(timeoutMs, () => {
      if (receivedBytes >= MIN_SPEED_BYTES) finish();
      else finish(new Error('target speed test timed out'));
      request.destroy();
    });
    request.on('error', (error) => {
      if (!settled) finish(error);
    });
    request.end();
  });
}

function createProbeServer(options = {}) {
  const token = String(options.token || process.env.PROBE_TOKEN || '').trim();
  const defaultSni = String(options.sni || process.env.PROBE_SNI || '121ko.albb.ccwu.cc').trim().toLowerCase();
  const allowedPorts = parseAllowedPorts(options.allowedPorts || process.env.PROBE_ALLOWED_PORTS);
  const defaultTimeoutMs = Math.min(10000, Math.max(500, Number(options.timeoutMs || process.env.PROBE_TIMEOUT_MS) || 3000));
  const probeFn = options.probeFn || probeCandidate;
  const speedFn = options.speedFn || measureCandidateSpeed;

  if (!token) throw new Error('PROBE_TOKEN is required');
  if (!isValidHostname(defaultSni)) throw new Error('PROBE_SNI must be a valid hostname');

  return http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url, 'http://probe-agent.local');
    if (requestUrl.pathname === '/health') {
      sendJson(response, 200, { ok: true, service: 'edgetunnel-probe-agent' });
      return;
    }
    if (requestUrl.pathname !== '/probe' && requestUrl.pathname !== '/speed') {
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
      let result;
      if (requestUrl.pathname === '/speed') {
        const bytes = parseSpeedBytes(requestUrl.searchParams.get('bytes'));
        const timeoutMs = Math.min(15000, Math.max(2000, Number(requestUrl.searchParams.get('timeout')) || 13000));
        result = await speedFn({ ip, port, sni, timeoutMs, bytes, token });
      } else {
        const timeoutMs = Math.min(10000, Math.max(500, Number(requestUrl.searchParams.get('timeout')) || defaultTimeoutMs));
        result = await probeFn({ ip, port, sni, timeoutMs });
      }
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
  server.requestTimeout = 20000;
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
  measureCandidateSpeed,
  parseAllowedPorts,
  parseSpeedBytes,
  probeCandidate
};
