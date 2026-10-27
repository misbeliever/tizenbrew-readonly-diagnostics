/* ES5 / Node 4.4.3. Fixed diagnostics only; never invoke a shell. */
(function () {
    'use strict';
    var http = require('http'), os = require('os'), fs = require('fs');
    var cp = require('child_process'), crypto = require('crypto');
    var origin = 'http://127.0.0.1:8081', port = 18766;
    var control = crypto.randomBytes(16).toString('hex');
    var report = null, busy = false, lan = null, lanURL = '', lanState = 'off';
    var nativeResult = { status: 'not run' }, sockets = [], expired = false;
    var appRoot = '/opt/usr/home/owner/apps_rw/xvvl3S1bvH';
    var binary = new Buffer('f0VMRgEBAQAAAAAAAAAAAAIAKAABAAAAtAACADQAAABcAQAAAAIABTQAIAAEACgABQAEAAYAAAA0AAAANAABADQAAQCAAAAAgAAAAAQAAAAEAAAAAQAAAAAAAAAAAAEAAAABALQAAAC0AAAABAAAAAAAAQABAAAAtAAAALQAAgC0AAIAPAAAADwAAAAFAAAAAAABAFHldGQAAAAAAAAAAAAAAAAAAAAAAAAAAQYAAAAAAAAAAQCg4xwQj+IUIKDjBHCg4wAAAO8UAFDjAQCgEwAAoAMBcKDjAAAA71RJWkVOX0RJQUdfQVJNVjdfT0sKQS4AAABhZWFiaQABJAAAAAVjb3J0ZXgtYTkABgoHQQgBCQIKAwwBIgEkASoBRAFMaW5rZXI6IExMRCAxOC4xLjYAAC50ZXh0AC5BUk0uYXR0cmlidXRlcwAuY29tbWVudAAuc2hzdHJ0YWIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAABAAAABgAAALQAAgC0AAAAPAAAAAAAAAAAAAAABAAAAAAAAAAHAAAAAwAAcAAAAAAAAAAA8AAAAC8AAAAAAAAAAAAAAAEAAAAAAAAAFwAAAAEAAAAwAAAAAAAAAB8BAAATAAAAAAAAAAAAAAABAAAAAQAAACAAAAADAAAAAAAAAAAAAAAyAQAAKgAAAAAAAAAAAAAAAQAAAAAAAAA=', 'base64');
    var binaryHash = 'ab157ae418f5e929f4657403de5ed3c5acfa46f7410b9d1d1c0dddf96e6bde9a';
    function errorCode(e) { return String(e.code || e.name || 'unavailable').slice(0, 60); }
    function observe(fn) { try { return fn(); } catch (e) { return { error: errorCode(e) }; } }
    function elf(b) {
        return { elf: b.length >= 52 && b.toString('hex', 0, 4) === '7f454c46',
            bits: b[4] === 1 ? 32 : 64, littleEndian: b[5] === 1,
            machine: b.length >= 52 ? b.readUInt16LE(18) : 0,
            eabi: b.length >= 52 ? b.readUInt32LE(36) >>> 24 : 0,
            flagsHex: b.length >= 52 ? '0x' + b.readUInt32LE(36).toString(16) : 'unavailable' };
    }
    function systemABI() {
        var fd, b = new Buffer(52);
        try { fd = fs.openSync('/bin/true', 'r');
            if (fs.readSync(fd, b, 0, 52, 0) !== 52) throw new Error('short ELF');
            return elf(b);
        } finally { if (fd !== undefined) fs.closeSync(fd); }
    }
    function probe(path, args, done) {
        try {
            fs.accessSync(path, fs.X_OK);
            cp.execFile(path, args, { timeout: 1000, killSignal: 'SIGKILL', maxBuffer: 4096,
                encoding: 'utf8', env: { LANG: 'C', LC_ALL: 'C' } }, function (e, out, err) {
                done({ status: e ? 'failed' : 'ok', code: e ? e.code : 0,
                    signal: e ? e.signal || null : null, killed: !!(e && e.killed),
                    stdout: String(out || '').slice(0, 4096), stderr: String(err || '').slice(0, 4096) });
            });
        } catch (e) { done({ status: 'failed', error: errorCode(e) }); }
    }
    function inspectPath(path) {
        return observe(function () {
            var stat = fs.statSync(path);
            return { type: stat.isDirectory() ? 'directory' : 'file',
                readable: observe(function () { fs.accessSync(path, fs.R_OK); return true; }),
                searchableOrExecutable: observe(function () { fs.accessSync(path, fs.X_OK); return true; }) };
        });
    }
    function boundedText(path, limit) {
        var fd, buffer = new Buffer(limit + 1), used = 0, n;
        try {
            fd = fs.openSync(path, 'r');
            do { n = fs.readSync(fd, buffer, used, buffer.length - used, null); used += n; }
            while (n > 0 && used < buffer.length);
            if (used > limit) { var e = new Error(); e.code = 'E2BIG'; throw e; }
            return buffer.toString('utf8', 0, used);
        } finally { if (fd !== undefined) fs.closeSync(fd); }
    }
    function permissions(path) {
        return observe(function () {
            var st = fs.statSync(path);
            return { modeOctal: (st.mode & 4095).toString(8), uid: st.uid, gid: st.gid,
                sizeBytes: st.size, type: st.isDirectory() ? 'directory' : 'file',
                executableAccess: observe(function () { fs.accessSync(path, fs.X_OK); return true; }) };
        });
    }
    function mountFor(text, target) {
        var best = null, ambiguous = false;
        text.split('\n').forEach(function (line) {
            var parts = line.split(' - '), fields = parts[0].split(' ');
            if (parts.length !== 2 || fields.length < 6) return;
            var point = fields[4].replace(/\\([0-7]{3})/g, function (_, code) { return String.fromCharCode(parseInt(code, 8)); });
            if (point !== '/' && target !== point && target.indexOf(point + '/') !== 0) return;
            if (best && point.length < best.point.length) return;
            if (best && point.length === best.point.length) { ambiguous = true; return; }
            best = { point: point, options: fields[5].split(','), fsType: parts[1].split(' ')[0] };
            ambiguous = false;
        });
        if (!best) return { status: 'unavailable', reason: 'No matching mount record' };
        // shortcut: stacked mounts are not resolved; report uncertainty rather than infer noexec.
        if (ambiguous) return { status: 'unavailable', reason: 'Multiple matching mounts at the same path' };
        return { status: 'observed', mountPoint: best.point.replace(appRoot, '<app>'),
            fsType: /^[a-zA-Z0-9_.-]{1,40}$/.test(best.fsType) ? best.fsType : 'redacted',
            options: best.options.filter(function (o) { return /^(ro|rw|nosuid|nodev|noexec|relatime|strictatime|noatime|nodiratime|sync|dirsync|lazytime)$/.test(o); }),
            noexec: best.options.indexOf('noexec') >= 0 };
    }
    function restrictions() {
        var mounts = observe(function () { return boundedText('/proc/self/mountinfo', 262144); });
        return {
            capturedAt: new Date().toISOString(),
            appDataMount: typeof mounts === 'string' ? mountFor(mounts, appRoot + '/data') : mounts,
            systemTrueMount: typeof mounts === 'string' ? mountFor(mounts, '/bin/true') : mounts,
            processStatus: observe(function () {
                var text = boundedText('/proc/self/status', 32768), result = {};
                ['NoNewPrivs', 'Seccomp', 'Seccomp_filters', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'].forEach(function (key) {
                    var match = new RegExp('^' + key + ':\\s*([a-fA-F0-9]+)\\s*$', 'm').exec(text);
                    result[key] = match ? match[1] : 'not reported';
                });
                return result;
            }),
            processSecurityLabel: observe(function () {
                return boundedText('/proc/self/attr/current', 256).replace(/[\x00-\x1f\x7f]/g, '').slice(0, 256);
            }),
            dataDirectory: permissions(appRoot + '/data'),
            systemTrue: permissions('/bin/true')
        };
    }
    function attributeReader() {
        var candidates = ['/usr/bin/getfattr', '/bin/getfattr'], checks = [], selected = null;
        candidates.forEach(function (path) {
            var check = observe(function () {
                var st = fs.statSync(path);
                if (!st.isFile() || st.uid !== 0 || (st.mode & 18) !== 0) return 'rejected ownership/type/mode';
                fs.accessSync(path, fs.X_OK);
                if (!selected) selected = path;
                return 'available';
            });
            checks.push({ path: path, result: check });
        });
        return { status: selected ? 'available' : 'unavailable', selected: selected, checks: checks };
    }
    function fileAttributes(reader, target, done) {
        if (!reader.selected) return done({ status: 'unavailable', reason: 'No permitted installed getfattr reader' });
        var names = ['security.SMACK64', 'security.SMACK64EXEC', 'security.SMACK64MMAP', 'security.ima', 'security.evm'];
        var result = { reader: reader.selected, attributes: {} }, index = 0;
        function next() {
            if (index === names.length) return done(result);
            var name = names[index++];
            try {
                cp.execFile(reader.selected, ['--absolute-names', '--only-values', '-n', name, '--', target], {
                    timeout: 1000, killSignal: 'SIGKILL', maxBuffer: 4096,
                    encoding: 'binary', env: { LANG: 'C', LC_ALL: 'C' }
                }, function (e, stdout) {
                    if (e) {
                        result.attributes[name] = { status: 'unavailable', code: e.code === undefined ? null : e.code,
                            signal: e.signal || null, killed: !!e.killed };
                    } else {
                        var value = new Buffer(stdout || '', 'binary');
                        if (name.indexOf('security.SMACK') === 0) {
                            var text = value.toString('utf8');
                            result.attributes[name] = value.length <= 256 && /^[\x20-\x7e]*$/.test(text) ?
                                { status: 'read', value: text } : { status: 'unavailable', reason: 'Unexpected label encoding/length' };
                        } else {
                            result.attributes[name] = { status: 'read', bytes: value.length,
                                sha256: crypto.createHash('sha256').update(value).digest('hex') };
                        }
                    }
                    next();
                });
            } catch (e) {
                result.attributes[name] = { status: 'unavailable', error: errorCode(e) };
                next();
            }
        }
        next();
    }
    function collect(done) {
        report = { diagnosticVersion: '1.4.0', capturedAt: new Date().toISOString(),
            node: process.version, v8: process.versions.v8, architecture: process.arch,
            platform: process.platform, osType: os.type(), kernelRelease: os.release(),
            uptimeSeconds: Math.floor(os.uptime()),
            expectedAppWorkingDirectory: process.cwd() === appRoot + '/res/wgt',
            uid: observe(function () { return process.getuid(); }),
            gid: observe(function () { return process.getgid(); }),
            effectiveUid: observe(function () { return process.geteuid(); }),
            effectiveGid: observe(function () { return process.getegid(); }),
            freeMemoryBytes: os.freemem(), totalMemoryBytes: os.totalmem(),
            tizenPlatform: observe(function () { return tizen.systeminfo.getCapability('http://tizen.org/feature/platform.version'); }),
            systemELF: observe(systemABI), probeELF: elf(binary), probeSHA256: binaryHash,
            fileSecurity: { reader: attributeReader(), signatureEnforcement: { status: 'undetermined',
                reason: 'No validated same-firmware verifier; metadata alone does not establish enforcement' } },
            restrictions: restrictions(), native: nativeResult, executables: {}, paths: {} };
        ['/', '/bin', '/bin/true', '/bin/uname', '/proc', '/proc/self', '/proc/self/status', '/tmp'].forEach(function (path) {
            report.paths[path] = inspectPath(path);
        });
        probe('/bin/true', [], function (r) { report.executables.true = r;
            probe('/bin/uname', ['-s', '-r', '-m'], function (r) { report.executables.uname = r;
                fileAttributes(report.fileSecurity.reader, '/bin/true', function (attrs) { report.fileSecurity.systemTrue = attrs; done(); });
            });
        });
    }
    function inspectNative(done) {
        var dir, file, created = false;
        function finish(result) {
            if (created) {
                result.cleanup = observe(function () {
                    try { fs.unlinkSync(file); } catch (e) { if (e.code !== 'ENOENT') throw e; }
                    fs.rmdirSync(dir); return 'removed';
                });
            }
            result.executionAttempted = false;
            nativeResult = result;
            if (report) report.native = result;
            done();
        }
        try {
            if (process.platform !== 'linux' || process.arch !== 'arm') {
                return finish({ status: 'skipped', reason: 'Not ARM Linux' });
            }
            var reader = attributeReader();
            if (!reader.selected) return finish({ status: 'skipped', reason: 'No permitted installed getfattr reader' });
            var abi = systemABI();
            if (!abi.elf ||
                abi.bits !== 32 || !abi.littleEndian || abi.machine !== 40 || abi.eabi !== 5) {
                return finish({ status: 'skipped', reason: 'ARM Linux EABI5 guard did not match' });
            }
            if (crypto.createHash('sha256').update(binary).digest('hex') !== binaryHash) throw new Error('probe integrity');
            // shortcut: verified 2.0.5 package layout only; reassess if app/package layout changes.
            if (process.cwd() !== appRoot + '/res/wgt' || fs.realpathSync(appRoot + '/data') !== appRoot + '/data') {
                return finish({ status: 'skipped', reason: 'Expected app-private data layout not verified' });
            }
            var stat = fs.statSync(appRoot + '/data');
            if (!stat.isDirectory() || stat.uid !== process.getuid()) {
                return finish({ status: 'skipped', reason: 'Data directory ownership did not match' });
            }
            fs.accessSync(appRoot + '/data', fs.W_OK | fs.X_OK);
            dir = appRoot + '/data/readonly-diag-' + crypto.randomBytes(8).toString('hex');
            fs.mkdirSync(dir, 448); created = true;
            file = dir + '/probe-armv7';
            fs.writeFileSync(file, binary, { flag: 'wx', mode: 448 });
            if (crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') !== binaryHash) throw new Error('written integrity');
            var inspection = { status: 'inspected', executionAttempted: false,
                capturedAt: new Date().toISOString(),
                directory: permissions(dir), file: permissions(file),
                fileMount: observe(function () { return mountFor(boundedText('/proc/self/mountinfo', 262144), file); }) };
            fileAttributes(reader, file, function (attrs) { inspection.fileSecurity = attrs; finish(inspection); });
        } catch (e) { finish({ status: 'failed', error: errorCode(e) }); }
    }
    function send(res, code, body, cors) {
        var headers = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Connection': 'close' };
        if (cors) headers['Access-Control-Allow-Origin'] = origin;
        res.writeHead(code, headers); res.end(JSON.stringify(body));
    }
    function stopLAN() {
        if (lan) lan.close(); lan = null; lanURL = ''; lanState = 'off';
        sockets.forEach(function (s) { s.destroy(); }); sockets = [];
    }
    function startLAN(done) {
        if (lan) return done();
        var addresses = [], interfaces = os.networkInterfaces();
        Object.keys(interfaces).forEach(function (name) { interfaces[name].forEach(function (a) {
            if (!a.internal && a.family === 'IPv4' && /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(a.address)) addresses.push(a.address);
        }); });
        if (!addresses.length) { lanState = 'No private IPv4 address found'; return done(); }
        var address = addresses[0], token = crypto.randomBytes(16).toString('hex');
        var endpoint = '/report/' + token, instance = http.createServer(function (req, res) {
            if (req.method !== 'GET' || req.url !== endpoint || req.headers.host !== address + ':18767' || req.headers.origin) {
                return send(res, 403, { error: 'Denied' });
            }
            send(res, report ? 200 : 503, report || { error: 'Run baseline first' });
        });
        lan = instance;
        instance.timeout = 3000;
        instance.on('connection', function (s) { sockets.push(s); s.on('close', function () {
            var i = sockets.indexOf(s); if (i >= 0) sockets.splice(i, 1);
        }); });
        instance.once('error', function () { stopLAN(); lanState = 'LAN bind failed'; done(); });
        instance.listen(18767, address, function () {
            if (expired) { stopLAN(); return done(); }
            lanURL = 'http://' + address + ':18767' + endpoint;
            lanState = 'On for 5 minutes (trusted LAN only)';
            setTimeout(function () { if (lan === instance) stopLAN(); }, 300000);
            done();
        });
    }
    function localState(res) { send(res, 200, { report: report, control: control, lanURL: lanURL, lanState: lanState }, true); }
    var server = http.createServer(function (req, res) {
        if (expired || req.headers.host !== '127.0.0.1:' + port || (req.headers.origin && req.headers.origin !== origin)) {
            return send(res, 403, { error: 'Denied' });
        }
        if (req.method === 'GET' && req.url === '/state') return localState(res);
        var match = /^\/(baseline|native|share|stop)\?key=([a-f0-9]{32})$/.exec(req.url);
        if (req.method !== 'POST' || req.headers.origin !== origin || !match || match[2] !== control) {
            return send(res, 403, { error: 'Denied' });
        }
        if (busy) return send(res, 429, { error: 'Busy; retry shortly' }, true);
        busy = true;
        function done() { busy = false; localState(res); }
        try {
            if (match[1] === 'baseline') collect(done);
            else if (match[1] === 'native') inspectNative(done);
            else if (match[1] === 'share') startLAN(done);
            else { stopLAN(); done(); }
        } catch (e) { busy = false; send(res, 500, { error: errorCode(e) }, true); }
    });
    server.timeout = 12000;
    server.on('error', function () { console.error('Diagnostics 1.4 loopback listener unavailable'); });
    server.listen(port, '127.0.0.1');
    setTimeout(function () { expired = true; stopLAN(); server.close(); }, 600000);
}());
