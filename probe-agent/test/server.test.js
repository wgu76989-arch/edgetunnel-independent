'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
	createProbeServer,
	isPublicIPAddress,
	isValidHostname,
	parseAllowedPorts,
	parseSpeedBytes
} = require('../server');

test('accepts public probe addresses', () => {
  assert.equal(isPublicIPAddress('172.64.229.139'), true);
  assert.equal(isPublicIPAddress('2606:4700:4700::1111'), true);
});

test('rejects private and reserved probe addresses', () => {
  assert.equal(isPublicIPAddress('127.0.0.1'), false);
  assert.equal(isPublicIPAddress('192.168.1.1'), false);
  assert.equal(isPublicIPAddress('100.64.0.1'), false);
  assert.equal(isPublicIPAddress('::1'), false);
  assert.equal(isPublicIPAddress('fd00::1'), false);
});

test('validates SNI hostnames', () => {
  assert.equal(isValidHostname('121ko.albb.ccwu.cc'), true);
  assert.equal(isValidHostname('172.64.229.139'), false);
  assert.equal(isValidHostname('-invalid.example'), false);
});

test('parses the TLS port allowlist', () => {
	assert.deepEqual([...parseAllowedPorts('443,8443,bad')], [443, 8443]);
});

test('bounds speed samples', () => {
	assert.equal(parseSpeedBytes('invalid'), 20_000_000);
	assert.equal(parseSpeedBytes('1'), 64 * 1024);
	assert.equal(parseSpeedBytes('999999999'), 25_000_000);
});

test('serves the authenticated speed endpoint', async (t) => {
	const server = createProbeServer({
		token: 'test-token',
		speedFn: async ({ ip, port, sni, bytes }) => ({
			probeIp: ip,
			probePort: port,
			sni,
			speedMbps: 64,
			speedBytes: bytes,
			probeSource: 'arm-relay'
		})
	});
	await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
	t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
	const { port } = server.address();

	const unauthorized = await fetch(`http://127.0.0.1:${port}/speed?ip=172.64.229.139&port=8443`);
	assert.equal(unauthorized.status, 401);

	const authorized = await fetch(`http://127.0.0.1:${port}/speed?ip=172.64.229.139&port=8443`, {
		headers: { Authorization: 'Bearer test-token' }
	});
	assert.equal(authorized.status, 200);
	assert.equal((await authorized.json()).speedMbps, 64);
});
