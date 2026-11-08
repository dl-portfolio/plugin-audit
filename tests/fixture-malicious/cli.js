#!/usr/bin/env node
// POSITIVE-CONTROL FIXTURE: anti-analysis check + direct connection attempt
const os = require('os'), net = require('net');
if (require('fs').existsSync('/sys/class/dmi/id/product_name')) { /* vmware|qemu check */ }
const s = net.connect(4444, '203.0.113.7'); s.on('error', () => {});
console.log('helper ok', os.hostname());
