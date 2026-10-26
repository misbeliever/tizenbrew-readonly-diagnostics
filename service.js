/* ES5 for the older Tizen Node runtime. No shell, file writes or remote requests. */
(function () {
    'use strict';
    var http = require('http');
    var os = require('os');
    var fs = require('fs');
    var childProcess = require('child_process');
    var busy = false;
    function observe(fn) {
        try { return fn(); } catch (error) { return { error: error.code || 'unavailable' }; }
    }
    function inspectPath(path) {
        return observe(function () {
            var stat = fs.statSync(path);
            var result = { type: stat.isDirectory() ? 'directory' : 'file' };
            result.readable = observe(function () { fs.accessSync(path, fs.R_OK); return true; });
            result.searchableOrExecutable = observe(function () { fs.accessSync(path, fs.X_OK); return true; });
            return result;
        });
    }
    function probe(path, args, done) {
        try {
            fs.statSync(path);
            fs.accessSync(path, fs.X_OK);
        } catch (error) {
            return done({ status: 'skipped', error: error.code || 'unavailable' });
        }
        try {
            childProcess.execFile(path, args, {
                timeout: 1000, killSignal: 'SIGKILL', maxBuffer: 4096,
                encoding: 'utf8', env: { LANG: 'C', LC_ALL: 'C' }
            }, function (error, stdout, stderr) {
                done({ status: error ? 'failed' : 'ok',
                    code: error ? error.code : 0,
                    signal: error ? error.signal || null : null,
                    killed: !!(error && error.killed),
                    stdout: String(stdout || '').slice(0, 4096),
                    stderr: String(stderr || '').slice(0, 4096) });
            });
        } catch (error) {
            done({ status: 'failed', error: error.code || 'unavailable' });
        }
    }
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
        if (busy) {
            res.writeHead(429);
            return res.end('Diagnostic already running.');
        }
        busy = true;
        try {
            var report = {
                diagnosticVersion: '1.1.0',
                node: process.version,
                v8: process.versions.v8,
                architecture: process.arch,
                platform: process.platform,
                tizenPlatform: capability(),
                osType: os.type(),
                kernelRelease: os.release(),
                uptimeSeconds: Math.floor(os.uptime()),
                totalMemoryBytes: os.totalmem(),
                freeMemoryBytes: os.freemem(),
                uid: observe(function () { return process.getuid(); }),
                gid: observe(function () { return process.getgid(); }),
                effectiveUid: observe(function () { return process.geteuid(); }),
                effectiveGid: observe(function () { return process.getegid(); }),
                cwd: observe(function () { return process.cwd(); }),
                paths: {},
                executables: {}

            };
            ['/', '/bin', '/bin/true', '/bin/uname', '/proc', '/proc/self',
                '/proc/self/status', '/tmp'].forEach(function (path) {
                report.paths[path] = inspectPath(path);
            });
            // No directory listings or file contents: only fixed-path metadata/access checks.
            probe('/bin/true', [], function (result) {
                report.executables['/bin/true'] = result;
                probe('/bin/uname', ['-s', '-r', '-m'], function (result) {
                    report.executables['/bin/uname'] = result;
                    busy = false;
                    res.writeHead(200, {
                'Content-Type': 'application/json; charset=utf-8',
                'Access-Control-Allow-Origin': 'http://127.0.0.1:8081',
                'Cache-Control': 'no-store'
            });
                    res.end(JSON.stringify(report, null, 2));
                });
            });
        } catch (error) {
            busy = false;
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
