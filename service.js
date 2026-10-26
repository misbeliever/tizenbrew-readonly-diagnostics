/* ES5 for the older Tizen Node runtime. No shell, file writes or remote requests. */
(function () {
    'use strict';
    var http = require('http');
    var os = require('os');
    function capability() {
        try {
            return tizen.systeminfo.getCapability('http://tizen.org/feature/platform.version');
        } catch (error) {
            return 'unavailable';
        }
    }
    var server = http.createServer(function (req, res) {
        if (req.method !== 'GET' || req.url !== '/report') {
            res.writeHead(404);
            return res.end();
        }
        if (req.headers.origin && req.headers.origin !== 'http://127.0.0.1:8081') {
            res.writeHead(403);
            return res.end();
        }
        try {
            var report = {
                diagnosticVersion: '1.0.0',
                node: process.version,
                v8: process.versions.v8,
                architecture: process.arch,
                platform: process.platform,
                tizenPlatform: capability(),
                osType: os.type(),
                kernelRelease: os.release(),
                uptimeSeconds: Math.floor(os.uptime()),
                totalMemoryBytes: os.totalmem(),
                freeMemoryBytes: os.freemem()
            };
            res.writeHead(200, {
                'Content-Type': 'application/json; charset=utf-8',
                'Access-Control-Allow-Origin': 'http://127.0.0.1:8081',
                'Cache-Control': 'no-store'
            });
            res.end(JSON.stringify(report, null, 2));
        } catch (error) {
            res.writeHead(500);
            res.end('Diagnostic read failed.');
        }
    });
    server.on('error', function () {
        console.error('Read-only Diagnostics: loopback listener unavailable; no retry.');
    });
    server.listen(18765, '127.0.0.1');
    setTimeout(function () { server.close(); }, 10 * 60 * 1000);
}());
