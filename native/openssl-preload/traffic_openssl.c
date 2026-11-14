#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* OpenSSL's opaque pointers keep this interposer buildable without its headers.
 * No OpenSSL structures are inspected. Custom BIOs without a socket are reported
 * as loss. The library stays loaded for the lifetime of the instrumented process. */
#define CONNECTIONS 4096
#define CHUNK_SIZE 12288
static pthread_once_t initialize_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t event_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread unsigned int call_depth;
static int event_socket = -1;
static char destination[sizeof(((struct sockaddr_un *)0)->sun_path)];
#define EVENT_SIZE (CHUNK_SIZE * 4 / 3 + 2 * NI_MAXHOST + 512)
#define EVENT_QUEUE 128
static struct queued_event { size_t length; uint64_t loss_count; char data[EVENT_SIZE]; } events[EVENT_QUEUE];
static size_t queue_head, queue_count;
static pthread_cond_t event_ready = PTHREAD_COND_INITIALIZER;
static pthread_t worker;
static int worker_running, stopping;
static uint64_t stop_deadline;
static uint64_t sequence, lost;
static pid_t identity_pid;
static char identity[96];
static struct connection { void *ssl; uint64_t generation; } connections[CONNECTIONS];
static int (*next_read)(void *, void *, int);
static int (*next_write)(void *, const void *, int);
static int (*next_read_ex)(void *, void *, size_t, size_t *);
static int (*next_write_ex)(void *, const void *, size_t, size_t *);
static int (*next_get_fd)(const void *);
static void *(*next_new)(void *);
static void (*next_free)(void *);

static void before_fork(void) { pthread_mutex_lock(&event_mutex); }
static void after_fork(void) { pthread_mutex_unlock(&event_mutex); }
static void child_after_fork(void) {
    if (event_socket >= 0) close(event_socket);
    event_socket = -1;
    lost = 0;
    queue_head = queue_count = 0;
    worker_running = stopping = 0;
    event_ready = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
    pthread_mutex_unlock(&event_mutex);
}

__attribute__((constructor)) static void register_fork_handlers(void) {
    pthread_atfork(before_fork, after_fork, child_after_fork);
}

static void initialize(void) {
    /* Python and other dlopen users may keep libssl in a local symbol scope. */
    const char *names[] = {"libssl.so.3", "libssl.so.1.1", "libssl.so.10", "libssl.so.1.0.0"};
    void *library = NULL;
    size_t i;
    const char *path = getenv("TRAFFIC_OPENSSL_SOCKET");
    if (path && strlen(path) < sizeof(destination)) strcpy(destination, path);
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        library = dlopen(names[i], RTLD_LAZY | RTLD_NOLOAD);
        if (library) break;
    }
#define RESOLVE(name, target) do { \
    *(void **)(&(target)) = dlsym(RTLD_NEXT, name); \
    if (!(target) && library) *(void **)(&(target)) = dlsym(library, name); \
} while (0)
    RESOLVE("SSL_read", next_read);
    RESOLVE("SSL_write", next_write);
    RESOLVE("SSL_read_ex", next_read_ex);
    RESOLVE("SSL_write_ex", next_write_ex);
    RESOLVE("SSL_get_fd", next_get_fd);
    RESOLVE("SSL_new", next_new);
    RESOLVE("SSL_free", next_free);
#undef RESOLVE
}

/* All event/socket/connection state is protected by event_mutex. Socket writes
 * are nonblocking so collector backpressure never blocks the application's I/O. */
static int transmit_event(const char *message, size_t length) {
    struct sockaddr_un address;
    ssize_t result;
    if (!destination[0]) return 0;
    if (event_socket < 0) {
        event_socket = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (event_socket < 0) return 0;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        strcpy(address.sun_path, destination);
        if (connect(event_socket, (struct sockaddr *)&address, sizeof(address)) != 0) {
            close(event_socket);
            event_socket = -1;
            return 0;
        }
    }
    result = send(event_socket, message, length, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (result == (ssize_t)length) return 1;
    if (result < 0 && (errno == ECONNREFUSED || errno == ENOENT)) {
        close(event_socket);
        event_socket = -1;
    }
    return 0;
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static void *send_worker(void *unused) {
    char message[EVENT_SIZE];
    size_t length, i;
    uint64_t loss_count;
    int sent;
    uint64_t deadline;
    (void)unused;
    for (;;) {
        pthread_mutex_lock(&event_mutex);
        while (!queue_count && !stopping) pthread_cond_wait(&event_ready, &event_mutex);
        if (!queue_count || (stopping && monotonic_milliseconds() >= stop_deadline)) {
            for (i = 0; i < queue_count; i++) lost += events[(queue_head + i) % EVENT_QUEUE].loss_count;
            queue_count = 0;
            pthread_mutex_unlock(&event_mutex);
            break;
        }
        length = events[queue_head].length;
        loss_count = events[queue_head].loss_count;
        memcpy(message, events[queue_head].data, length);
        queue_head = (queue_head + 1) % EVENT_QUEUE;
        queue_count--;
        pthread_mutex_unlock(&event_mutex);
        deadline = monotonic_milliseconds() + 100;
        do {
            sent = transmit_event(message, length);
            if (sent || event_socket < 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) break;
            { struct pollfd writable = {event_socket, POLLOUT, 0}; poll(&writable, 1, 5); }
        } while (monotonic_milliseconds() < deadline);
        if (!sent) {
            pthread_mutex_lock(&event_mutex);
            lost += loss_count;
            /* Drop queued tail data after a transport gap. The next application
             * event enqueues the loss marker before any fresh plaintext. */
            for (i = 0; i < queue_count; i++) lost += events[(queue_head + i) % EVENT_QUEUE].loss_count;
            queue_count = 0;
            pthread_mutex_unlock(&event_mutex);
        }
    }
    return NULL;
}

/* Called with event_mutex held. Application threads copy into a bounded queue
 * and never wait for collector socket backpressure. */
static int send_event(const char *message, size_t length) {
    size_t tail;
    if (!destination[0] || stopping || length > EVENT_SIZE || queue_count == EVENT_QUEUE) return 0;
    if (!worker_running) {
        if (pthread_create(&worker, NULL, send_worker, NULL)) return 0;
        worker_running = 1;
    }
    tail = (queue_head + queue_count) % EVENT_QUEUE;
    memcpy(events[tail].data, message, length);
    events[tail].length = length;
    events[tail].loss_count = 1;
    queue_count++;
    pthread_cond_signal(&event_ready);
    return 1;
}

static void refresh_identity(void) {
    FILE *file;
    char stat[4096], *end, *token, *saved;
    unsigned int i;
    pid_t pid = getpid();
    if (identity_pid == pid) return;
    identity[0] = 0;
    file = fopen("/proc/self/stat", "r");
    if (!file) return;
    end = fgets(stat, sizeof(stat), file);
    fclose(file);
    if (!end || !(end = strrchr(stat, ')'))) return;
    token = strtok_r(end + 1, " ", &saved);
    for (i = 0; i < 19 && token; i++) token = strtok_r(NULL, " ", &saved);
    if (!token) return;
    snprintf(identity, sizeof(identity), "%ld:%s", (long)pid, token);
    identity_pid = pid;
}

static void report_loss(void) {
    char message[256];
    int length;
    refresh_identity();
    if (!lost) return;
    length = snprintf(message, sizeof(message),
        "{\"protocol\":\"traffic-openssl-v1\",\"type\":\"loss\",\"process_id\":\"%s\",\"count\":%llu}",
        identity, (unsigned long long)lost);
    if (send_event(message, (size_t)length)) {
        events[(queue_head + queue_count - 1) % EVENT_QUEUE].loss_count = lost;
        lost = 0;
    }
}

static struct connection *find_connection(void *ssl, int create) {
    size_t i, empty = CONNECTIONS;
    for (i = 0; i < CONNECTIONS; i++) {
        if (connections[i].ssl == ssl) return &connections[i];
        if (!connections[i].ssl && empty == CONNECTIONS) empty = i;
    }
    if (!create || empty == CONNECTIONS) return NULL;
    connections[empty].ssl = ssl;
    connections[empty].generation = ++sequence;
    return &connections[empty];
}

static int endpoint(int fd, int peer, char *output, size_t capacity) {
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    char host[NI_MAXHOST], port[NI_MAXSERV];
    int result = peer ? getpeername(fd, (struct sockaddr *)&address, &length)
                      : getsockname(fd, (struct sockaddr *)&address, &length);
    if (result || (address.ss_family != AF_INET && address.ss_family != AF_INET6)) return 0;
    if (getnameinfo((struct sockaddr *)&address, length, host, sizeof(host), port,
                   sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV)) return 0;
    snprintf(output, capacity, address.ss_family == AF_INET6 ? "[%s]:%s" : "%s:%s", host, port);
    return 1;
}

static size_t encode_base64(char *output, const unsigned char *input, size_t length) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, used = 0;
    for (i = 0; i < length; i += 3) {
        uint32_t value = (uint32_t)input[i] << 16;
        if (i + 1 < length) value |= (uint32_t)input[i + 1] << 8;
        if (i + 2 < length) value |= input[i + 2];
        output[used++] = alphabet[(value >> 18) & 63];
        output[used++] = alphabet[(value >> 12) & 63];
        output[used++] = i + 1 < length ? alphabet[(value >> 6) & 63] : '=';
        output[used++] = i + 2 < length ? alphabet[value & 63] : '=';
    }
    return used;
}

static void emit_data(void *ssl, const void *buffer, size_t length, const char *direction) {
    char local[NI_MAXHOST + NI_MAXSERV + 4], peer[NI_MAXHOST + NI_MAXSERV + 4];
    char message[CHUNK_SIZE * 4 / 3 + 2 * NI_MAXHOST + 512];
    const unsigned char *bytes = buffer;
    struct connection *connection;
    int fd, header;
    size_t chunk, used;
    if (!destination[0] || !length) return;
    pthread_mutex_lock(&event_mutex);
    report_loss();
    fd = next_get_fd ? next_get_fd(ssl) : -1;
    connection = find_connection(ssl, 1);
    if (!connection || fd < 0 || !endpoint(fd, 0, local, sizeof(local)) ||
        !endpoint(fd, 1, peer, sizeof(peer))) {
        lost++;
        pthread_mutex_unlock(&event_mutex);
        return;
    }
    while (length) {
        chunk = length < CHUNK_SIZE ? length : CHUNK_SIZE;
        report_loss();
        header = snprintf(message, sizeof(message),
            "{\"protocol\":\"traffic-openssl-v1\",\"type\":\"data\",\"connection\":\"%ld-%p-%llu\","
            "\"process_id\":\"%s\",\"direction\":\"%s\",\"local\":\"%s\",\"client\":\"%s\",\"data_b64\":\"",
            (long)getpid(), ssl, (unsigned long long)connection->generation, identity, direction, local, peer);
        used = (size_t)header;
        used += encode_base64(message + used, bytes, chunk);
        memcpy(message + used, "\"}", 2);
        if (!send_event(message, used + 2)) lost++;
        bytes += chunk;
        length -= chunk;
    }
    pthread_mutex_unlock(&event_mutex);
}

void *SSL_new(void *context) {
    void *ssl;
    int saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_new) { errno = ENOSYS; return NULL; }
    ssl = next_new(context);
    saved_errno = errno;
    if (ssl && destination[0]) {
        pthread_mutex_lock(&event_mutex);
        if (!find_connection(ssl, 1)) lost++;
        pthread_mutex_unlock(&event_mutex);
    }
    errno = saved_errno;
    return ssl;
}

void SSL_free(void *ssl) {
    char message[384];
    struct connection *connection;
    int length, saved_errno = errno;
    pthread_once(&initialize_once, initialize);
    if (ssl && destination[0]) {
        pthread_mutex_lock(&event_mutex);
        report_loss();
        connection = find_connection(ssl, 0);
        if (connection) {
            length = snprintf(message, sizeof(message),
                "{\"protocol\":\"traffic-openssl-v1\",\"type\":\"close\",\"process_id\":\"%s\",\"connection\":\"%ld-%p-%llu\"}",
                identity, (long)getpid(), ssl, (unsigned long long)connection->generation);
            if (!send_event(message, (size_t)length)) lost++;
            connection->ssl = NULL;
        }
        pthread_mutex_unlock(&event_mutex);
    }
    errno = saved_errno;
    if (next_free) next_free(ssl);
}

int SSL_read(void *ssl, void *buffer, int length) {
    int result, saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_read) { errno = ENOSYS; return -1; }
    call_depth++;
    result = next_read(ssl, buffer, length);
    saved_errno = errno;
    if (--call_depth == 0 && result > 0) emit_data(ssl, buffer, (size_t)result, "read");
    errno = saved_errno;
    return result;
}

int SSL_write(void *ssl, const void *buffer, int length) {
    int result, saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_write) { errno = ENOSYS; return -1; }
    call_depth++;
    result = next_write(ssl, buffer, length);
    saved_errno = errno;
    if (--call_depth == 0 && result > 0) emit_data(ssl, buffer, (size_t)result, "write");
    errno = saved_errno;
    return result;
}

int SSL_read_ex(void *ssl, void *buffer, size_t length, size_t *read_bytes) {
    int result, saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_read_ex) { errno = ENOSYS; return 0; }
    call_depth++;
    result = next_read_ex(ssl, buffer, length, read_bytes);
    saved_errno = errno;
    if (--call_depth == 0 && result == 1 && read_bytes) emit_data(ssl, buffer, *read_bytes, "read");
    errno = saved_errno;
    return result;
}

int SSL_write_ex(void *ssl, const void *buffer, size_t length, size_t *written_bytes) {
    int result, saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_write_ex) { errno = ENOSYS; return 0; }
    call_depth++;
    result = next_write_ex(ssl, buffer, length, written_bytes);
    saved_errno = errno;
    if (--call_depth == 0 && result == 1 && written_bytes) emit_data(ssl, buffer, *written_bytes, "write");
    errno = saved_errno;
    return result;
}

__attribute__((destructor)) static void shutdown_events(void) {
    int join;
    pthread_mutex_lock(&event_mutex);
    report_loss();
    stopping = 1;
    stop_deadline = monotonic_milliseconds() + 500;
    join = worker_running;
    pthread_cond_signal(&event_ready);
    pthread_mutex_unlock(&event_mutex);
    if (join) pthread_join(worker, NULL);
    if (event_socket >= 0) close(event_socket);
}
