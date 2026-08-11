'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  isPublicIPAddress,
  isValidHostname,
  parseAllowedPorts
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
  assert.equal(isValidHostname('eee21.albb.ccwu.cc'), true);
  assert.equal(isValidHostname('172.64.229.139'), false);
  assert.equal(isValidHostname('-invalid.example'), false);
});

test('parses the TLS port allowlist', () => {
  assert.deepEqual([...parseAllowedPorts('443,8443,bad')], [443, 8443]);
});
