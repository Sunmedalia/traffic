'use strict';

// Only public OpenSSL APIs are called. Static builds require a hash-pinned profile.
const selectedPorts = new Set(__PORTS__);
const profiles = __PROFILES__;
const library = __LIBRARY__;
const copyLimit = Math.max(__REQUEST_LIMIT__, __RESPONSE_LIMIT__) + 65536;
const listeners = [];
const originals = new Map();
const connections = new Map();
const depth = new Map();
let sequence = 0;
let stopping = false;
let events = [];
let queuedBytes = 0;
let dropped = 0;
let captured = 0;

function enqueue(event, data = null) {
    const size = data === null ? 0 : data.byteLength;
    if (events.length >= 256 || queuedBytes + size > 8 * 1024 * 1024) { dropped++; return; }
    event.time = new Date().toISOString();
    events.push({event, data});
    queuedBytes += size;
}
function flush() {
    if (dropped) { send({type: 'loss', count: dropped}); dropped = 0; }
    const batch = events;
    events = [];
    queuedBytes = 0;
    for (const item of batch) send(item.event, item.data);
}
function hook(address, callbacks) {
    if (!originals.has(address.toString())) originals.set(address.toString(), new Uint8Array(address.readByteArray(16)));
    listeners.push(Interceptor.attach(address, callbacks));
}
function endpoint(address) {
    return address.ip.includes(':') ? '[' + address.ip + ']:' + address.port : address.ip + ':' + address.port;
}
function apacheSocket(module) {
    if (!['httpd.exe', 'apache.exe', 'apache2.exe'].includes(Process.mainModule.name.toLowerCase())) return null;
    const httpd = Process.findModuleByName('libhttpd.dll');
    const apr = Process.findModuleByName('libapr-1.dll');
    const exDataAddress = module.findExportByName('SSL_get_ex_data');
    if (httpd === null || apr === null || exDataAddress === null) return null;
    const abi = Process.arch === 'ia32' ? 'mscdecl' : 'win64';
    const exData = new NativeFunction(exDataAddress, 'pointer', ['pointer', 'int'], abi);
    const connSocket = new NativeFunction(httpd.getExportByName('ap_get_conn_socket'), 'pointer', ['pointer'], abi);
    const osSocket = new NativeFunction(apr.getExportByName('apr_os_sock_get'), 'int', ['pointer', 'pointer'], abi);
    // mod_ssl stores conn_rec in public OpenSSL app_data (ex_data index zero).
    // Apache's custom BIO does not expose a descriptor through SSL_get_fd.
    return ssl => {
        const conn = exData(ssl, 0);
        if (conn.isNull()) return -1;
        const socket = connSocket(conn);
        if (socket.isNull()) return -1;
        const result = Memory.alloc(Process.pointerSize);
        return osSocket(result, socket) === 0 ? result.readPointer().toInt32() : -1;
    };
}
function connection(ssl, getFD, fallback, module) {
    let fd = getFD(ssl);
    if (fd < 0 && fallback !== null) fd = fallback(ssl);
    if (fd < 0) { dropped++; return null; }
    const local = Socket.localAddress(fd);
    const remote = Socket.peerAddress(fd);
    if (local === null || remote === null) { dropped++; return null; }
    if (!selectedPorts.has(local.port) && !selectedPorts.has(remote.port)) return null;
    const key = module + ':' + ssl;
    const signature = fd + '/' + endpoint(local) + '/' + endpoint(remote);
    let state = connections.get(key);
    if (state === undefined || state.signature !== signature) {
        if (connections.size >= 4096) { dropped++; return null; }
        state = {id: String(++sequence), fd, signature, local: endpoint(local), remote: endpoint(remote)};
        connections.set(key, state);
    }
    return state;
}
function resolve(module) {
    if (library && module.name.toLowerCase() !== library.toLowerCase() && module.path.toLowerCase() !== library.toLowerCase()) return null;
    const names = ['SSL_read', 'SSL_write', 'SSL_read_ex', 'SSL_write_ex', 'SSL_get_fd'];
    const addresses = {};
    for (const name of names) addresses[name] = module.findExportByName(name);
    if (addresses.SSL_get_fd && (addresses.SSL_read || addresses.SSL_read_ex) && (addresses.SSL_write || addresses.SSL_write_ex)) return addresses;
    const candidates = profiles.filter(profile => profile.module.toLowerCase() === module.name.toLowerCase() && profile.arch === Process.arch);
    if (candidates.length === 0) return null;
    const hash = Checksum.compute('sha256', File.readAllBytes(module.path));
    const profile = candidates.find(candidate => candidate.sha256 === hash);
    if (profile === undefined) return null;
    for (const name of names) {
        const entry = profile.functions[name];
        addresses[name] = entry === undefined ? null : module.base.add(entry.rva);
        if (entry !== undefined) {
            const actual = Array.from(new Uint8Array(addresses[name].readByteArray(entry.bytes.length / 2))).map(value => value.toString(16).padStart(2, '0')).join('');
            if (actual !== entry.bytes) throw new Error('Static OpenSSL function check failed: ' + name);
        }
    }
    if (!addresses.SSL_get_fd || !(addresses.SSL_read || addresses.SSL_read_ex) || !(addresses.SSL_write || addresses.SSL_write_ex)) throw new Error('Incomplete static OpenSSL profile');
    return addresses;
}
const installed = [];
function install(module) {
    const addresses = resolve(module);
    if (addresses === null) return;
    const getFD = new NativeFunction(addresses.SSL_get_fd, 'int', ['pointer'], Process.arch === 'ia32' ? 'mscdecl' : 'win64');
    const fallback = apacheSocket(module);
    for (const name of ['SSL_read', 'SSL_write', 'SSL_read_ex', 'SSL_write_ex']) {
        if (!addresses[name]) continue;
        const direction = name.startsWith('SSL_read') ? 'read' : 'write';
        const extended = name.endsWith('_ex');
        hook(addresses[name], {
            onEnter(args) {
                if (stopping) return;
                this.depthKey = this.threadId + ':' + direction;
                const nesting = depth.get(this.depthKey) || 0;
                depth.set(this.depthKey, nesting + 1);
                if (nesting !== 0) return;
                try {
                    this.state = connection(args[0], getFD, fallback, module.name);
                    if (this.state === null) return;
                    this.buffer = args[1];
                    this.capacity = Math.min(extended ? Number(args[2].toString()) : args[2].toUInt32(), copyLimit);
                    this.resultSize = extended ? args[3] : null;
                    if (direction === 'write') this.copy = this.buffer.readByteArray(this.capacity);
                } catch (error) { this.state = null; dropped++; }
            },
            onLeave(result) {
                if (this.depthKey === undefined) return;
                const nesting = (depth.get(this.depthKey) || 1) - 1;
                if (nesting === 0) depth.delete(this.depthKey); else depth.set(this.depthKey, nesting);
                if (stopping || this.state === undefined || this.state === null) return;
                try {
                    const status = result.toInt32();
                    if (status <= 0) return;
                    const length = extended ? (Process.pointerSize === 8 ? Number(this.resultSize.readU64()) : this.resultSize.readU32()) : status;
                    if (length <= 0) return;
                    const count = Math.min(length, this.capacity);
                    const data = direction === 'write' ? this.copy.slice(0, count) : this.buffer.readByteArray(count);
                    enqueue({type: 'data', connection: this.state.id, direction, local: this.state.local, client: this.state.remote, incomplete: length > count}, data);
                    captured++;
                } catch (error) { dropped++; }
            }
        });
    }
    installed.push(module.name);
}
const observer = Process.attachModuleObserver({
    onAdded(module) {
        if (stopping) return;
        try { install(module); } catch (error) { send({type: 'error', message: String(error)}); }
    }
});
const winsock = Process.getModuleByName('ws2_32.dll');
hook(winsock.getExportByName('closesocket'), {
    onEnter(args) {
        if (stopping) return;
        const fd = args[0].toInt32();
        for (const [key, state] of connections) {
            if (state.fd === fd) { enqueue({type: 'close', connection: state.id}); connections.delete(key); }
        }
    }
});
const timer = setInterval(flush, 50);
// A process may load its TLS DLL later. Go exposes ready only after hooks exist.
const readinessDeadline = setTimeout(() => {
    if (installed.length === 0) send({type: 'error', message: 'No supported OpenSSL exports or matching static binary profile. Check --libssl and --openssl-profile.'});
}, 10000);
const readyTimer = setInterval(() => {
    if (installed.length === 0) return;
    enqueue({type: 'ready', protocol: 'traffic-openssl-v1', modules: installed, arch: Process.arch});
    clearInterval(readyTimer);
}, 100);
rpc.exports = {
    finish() {
        stopping = true;
        observer.detach();
        clearInterval(timer);
        clearInterval(readyTimer);
        clearTimeout(readinessDeadline);
        for (const listener of listeners) listener.detach();
        Interceptor.flush();
        let restored = true;
        for (const [address, original] of originals) {
            const actual = new Uint8Array(ptr(address).readByteArray(16));
            if (original.some((value, index) => value !== actual[index])) restored = false;
        }
        flush();
        return {type: 'summary', captured, hooks_removed: restored, restored_sites: originals.size, modules: installed};
    }
};
