#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <stdint.h>
/* GCC builtins keep the old-kernel backend buildable with CentOS 7 GCC 4.8. */
#define atomic_load(p) __atomic_load_n((p), __ATOMIC_RELAXED)
#define atomic_store(p, v) __atomic_store_n((p), (v), __ATOMIC_RELAXED)
#define atomic_exchange(p, v) __atomic_exchange_n((p), (v), __ATOMIC_RELAXED)
#define atomic_fetch_add(p, v) __atomic_fetch_add((p), (v), __ATOMIC_RELAXED)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* OpenSSL's opaque pointers keep this interposer buildable without its headers.
 * No OpenSSL structures are inspected. Custom BIOs without a socket are
 * reported as loss. The library stays loaded for the lifetime of the
 * instrumented process. */
#define CONNECTIONS 4096
#define CHUNK_SIZE 12288
static pthread_once_t initialize_once = PTHREAD_ONCE_INIT;
#define CONNECTION_STRIPES 64
#define CONNECTION_WIDTH (CONNECTIONS / CONNECTION_STRIPES)
static pthread_mutex_t connection_mutex[CONNECTION_STRIPES] = {
    [0 ... CONNECTION_STRIPES - 1] = PTHREAD_MUTEX_INITIALIZER
};
static uint64_t connection_hash(void *ssl) {
    uint64_t value = (uintptr_t)ssl >> 4;
    value ^= value >> 17;
    value *= UINT64_C(0x9e3779b97f4a7c15);
    return value ^ (value >> 32);
}
static pthread_mutex_t *connection_lock(void *ssl) {
    return &connection_mutex[connection_hash(ssl) % CONNECTION_STRIPES];
}
static __thread unsigned int call_depth;
static int event_socket = -1;
static char destination[sizeof(((struct sockaddr_un *)0)->sun_path)];
static char debug_path[256];
#define EVENT_SIZE (CHUNK_SIZE * 4 / 3 + 2 * NI_MAXHOST + 512)
#define EVENT_QUEUE 128
struct raw_event {
    char local[128], peer[128], identity[96], direction[6];
    pid_t pid;
    void *ssl;
    uint64_t generation;
    unsigned char bytes[CHUNK_SIZE];
};
static struct queued_event {
    uint64_t available, published, position;
    size_t length;
    uint64_t loss_count;
    int raw;
    union {
        char data[EVENT_SIZE];
        struct raw_event body;
    } payload;
} events[EVENT_QUEUE];
static uint64_t contention_lost;
static uint64_t cooldown_lost, queue_lost, metadata_lost, metadata_pending, transport_lost;
static int transport_errno;
static uint64_t retry_after;
/* Producers claim monotonic tickets with CAS; the worker alone advances read.
 * Each slot publishes its ticket so an old ready flag cannot survive reuse. */
static uint64_t queue_write, queue_read;
static pthread_mutex_t wait_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t transport_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t worker_once = PTHREAD_ONCE_INIT;
static pthread_cond_t event_ready;
static int event_ready_initialized;
static pthread_t worker;
static int worker_running, worker_sleeping, stopping;
static uint64_t stop_deadline;
static uint64_t sequence, lost, metadata_epoch;
static pid_t identity_pid;
static char identity[96];
static size_t identity_len = 1;
static struct connection {
    void *ssl;
    uint64_t generation, epoch;
    int fd;
    uint8_t local_len, peer_len;
    char local[128], peer[128];
} connections[CONNECTION_STRIPES][CONNECTION_WIDTH];
static int (*next_read)(void *, void *, int);
static int (*next_write)(void *, const void *, int);
static int (*next_read_ex)(void *, void *, size_t, size_t *);
static int (*next_write_ex)(void *, const void *, size_t, size_t *);
static int (*next_get_fd)(const void *);
static int (*next_set_fd)(void *, int);
static void *(*next_new)(void *);
static void (*next_free)(void *);

static int initialize_event_ready(void) {
    pthread_condattr_t attr;
    int error = pthread_condattr_init(&attr);
    if (error)
        return 0;
    error = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (!error)
        error = pthread_cond_init(&event_ready, &attr);
    pthread_condattr_destroy(&attr);
    return !error;
}

static void before_fork(void) {
    for (int i = 0; i < CONNECTION_STRIPES; i++)
        pthread_mutex_lock(&connection_mutex[i]);
    pthread_mutex_lock(&transport_mutex);
}
static void after_fork(void) {
    pthread_mutex_unlock(&transport_mutex);
    for (int i = CONNECTION_STRIPES - 1; i >= 0; i--)
        pthread_mutex_unlock(&connection_mutex[i]);
}
static void child_after_fork(void) {
    if (event_socket >= 0)
        close(event_socket);
    event_socket = -1;
    atomic_store(&lost, 0);
    queue_write = queue_read = 0;
    for (size_t i = 0; i < EVENT_QUEUE; i++) {
        events[i].available = i;
        events[i].published = 0;
    }
    worker_once = (pthread_once_t)PTHREAD_ONCE_INIT;
    wait_mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    worker_running = worker_sleeping = stopping = 0;
    atomic_store(&retry_after, 0);
    atomic_store(&contention_lost, 0);
    atomic_store(&cooldown_lost, 0);
    atomic_store(&metadata_pending, 0);
    queue_lost = metadata_lost = transport_lost = 0;
    transport_errno = 0;
    /* The child has no worker to release any inherited waiters. */
    memset(&event_ready, 0, sizeof(event_ready));
    event_ready_initialized = initialize_event_ready();
    pthread_mutex_unlock(&transport_mutex);
    for (int i = CONNECTION_STRIPES - 1; i >= 0; i--)
        pthread_mutex_unlock(&connection_mutex[i]);
}

__attribute__((constructor)) static void register_fork_handlers(void) {
    event_ready_initialized = initialize_event_ready();
    pthread_atfork(before_fork, after_fork, child_after_fork);
}

static char *trim(char *text) {
    char *end;
    while (*text && isspace((unsigned char)*text))
        text++;
    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1]))
        end--;
    *end = 0;
    return text;
}

static void debug_note(const char *state) {
    char message[512], comm[64] = "";
    FILE *file;
    int fd, length;
    if (!debug_path[0])
        return;
    file = fopen("/proc/self/comm", "r");
    if (file) {
        if (!fgets(comm, sizeof(comm), file))
            comm[0] = 0;
        fclose(file);
        trim(comm);
    }
    length = snprintf(message, sizeof(message),
                      "pid=%ld comm=%s %s destination=%s\n", (long)getpid(),
                      comm, state, destination);
    if (length < 0 || (size_t)length >= sizeof(message))
        return;
    fd = open(debug_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    if (write(fd, message, (size_t)length) < 0) { /* diagnostics only */
    }
    close(fd);
}

/* /etc/ld.so.preload cannot set environment variables, so a root-owned config
 * file selects the socket and the process names that may report. Without the
 * config (or with a non-matching comm) the interposer stays inert, which makes
 * a system-wide preload safe for unrelated TLS clients such as sshd. */
static void load_config(void) {
    const char *config;
    FILE *file;
    char line[512], socket_path[sizeof(destination)] = "", targets[256] = "";
    char *key, *value;
    if (!getenv("TRAFFIC_OPENSSL_SOCKET")) {
        config = getenv("TRAFFIC_OPENSSL_CONFIG");
        if (!config || !*config)
            config = "/etc/traffic/openssl-preload.conf";
        file = fopen(config, "r");
        if (!file)
            return;
        while (fgets(line, sizeof(line), file)) {
            value = strchr(line, '=');
            if (!value)
                continue;
            *value++ = 0;
            key = trim(line);
            value = trim(value);
            if (!strcmp(key, "socket") && strlen(value) < sizeof(socket_path)) {
                strcpy(socket_path, value);
            } else if (!strcmp(key, "targets") &&
                       strlen(value) < sizeof(targets)) {
                strcpy(targets, value);
            } else if (!strcmp(key, "debug_file") &&
                       strlen(value) < sizeof(debug_path)) {
                strcpy(debug_path, value);
            }
        }
        fclose(file);
        if (!socket_path[0])
            return;
        if (targets[0] && strcmp(targets, "*") != 0) {
            char comm[64] = "", *entry, *saved = NULL;
            int matched = 0;
            file = fopen("/proc/self/comm", "r");
            if (!file)
                return;
            if (!fgets(comm, sizeof(comm), file))
                comm[0] = 0;
            fclose(file);
            trim(comm);
            for (entry = strtok_r(targets, ",", &saved); entry;
                 entry = strtok_r(NULL, ",", &saved)) {
                size_t length;
                entry = trim(entry);
                length = strlen(entry);
                if (length && entry[length - 1] == '*') {
                    if (!strncmp(comm, entry, length - 1))
                        matched = 1;
                } else if (!strcmp(comm, entry)) {
                    matched = 1;
                }
            }
            if (!matched)
                return;
        }
        strcpy(destination, socket_path);
    }
}

static void initialize(void) {
    /* Python and other dlopen users may keep libssl in a local symbol scope. */
    const char *names[] = {"libssl.so.3", "libssl.so.1.1", "libssl.so.10",
                           "libssl.so.1.0.0"};
    void *library = NULL;
    size_t i;
    const char *path = getenv("TRAFFIC_OPENSSL_SOCKET");
    if (path && strlen(path) < sizeof(destination))
        strcpy(destination, path);
    else
        load_config();
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        library = dlopen(names[i], RTLD_LAZY | RTLD_NOLOAD);
        if (library)
            break;
    }
#define RESOLVE(name, target)                                                  \
    do {                                                                       \
        *(void **)(&(target)) = dlsym(RTLD_NEXT, name);                        \
        if (!(target) && library)                                              \
            *(void **)(&(target)) = dlsym(library, name);                      \
    } while (0)
    RESOLVE("SSL_read", next_read);
    RESOLVE("SSL_write", next_write);
    RESOLVE("SSL_read_ex", next_read_ex);
    RESOLVE("SSL_write_ex", next_write_ex);
    RESOLVE("SSL_get_fd", next_get_fd);
    RESOLVE("SSL_set_fd", next_set_fd);
    RESOLVE("SSL_new", next_new);
    RESOLVE("SSL_free", next_free);
#undef RESOLVE
    debug_note(library && next_read ? "initialized" : "symbols-missing");
}

/* Socket I/O belongs exclusively to the worker; producers never wait for it. */
static int transmit_event(const char *message, size_t length) {
    struct sockaddr_un address;
    ssize_t result;
    if (!destination[0])
        return EDESTADDRREQ;
    if (event_socket < 0) {
        event_socket =
            socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (event_socket < 0)
            return errno;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        strcpy(address.sun_path, destination);
        if (connect(event_socket, (struct sockaddr *)&address,
                    sizeof(address)) != 0) {
            int error = errno;
            close(event_socket);
            event_socket = -1;
            return error;
        }
    }
    result = send(event_socket, message, length, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (result == (ssize_t)length)
        return 0;
    int error = result < 0 ? errno : EIO;
    if (error == ECONNREFUSED || error == ENOENT || error == EPIPE ||
        error == ENOTCONN || error == EDESTADDRREQ) {
        close(event_socket);
        event_socket = -1;
    }
    return error;
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

/* Only retry short producer contention, never wait for collector I/O. */
static int acquire_event_lock(pthread_mutex_t *mutex) {
    if (!pthread_mutex_trylock(mutex))
        return 1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t deadline =
        (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec + 25000;
    do {
        if (!pthread_mutex_trylock(mutex))
            return 1;
#if defined(__x86_64__) || defined(__i386__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while ((uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec <
             deadline);
    /* A scheduling pause may have exhausted the wall-clock budget just as
     * the owner released the lock. One nonblocking final try avoids a false
     * drop without extending the spin budget. */
    return !pthread_mutex_trylock(mutex);
}

static size_t encode_base64(char *, const unsigned char *, size_t);
/* Diagnostic snapshot; slot availability alone decides admission. */
static uint64_t queue_length(void) {
    uint64_t read = __atomic_load_n(&queue_read, __ATOMIC_ACQUIRE);
    uint64_t length = atomic_load(&queue_write) - read;
    return length > EVENT_QUEUE ? EVENT_QUEUE : length;
}
/* Bounded MPSC reservation. An unavailable slot never blocks a TLS caller. */
static struct queued_event *reserve_event(size_t length, int raw, uint64_t loss_count) {
    for (int attempt = 0; attempt < 64; attempt++) {
        uint64_t position = atomic_load(&queue_write);
        struct queued_event *event = &events[position % EVENT_QUEUE];
        uint64_t available = __atomic_load_n(&event->available, __ATOMIC_ACQUIRE);
        if (__atomic_load_n(&stopping, __ATOMIC_ACQUIRE) || available < position)
            return NULL;
        if (available != position)
            continue;
        uint64_t expected = position;
        if (!__atomic_compare_exchange_n(&queue_write, &expected, position + 1, 0,
                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            continue;
        event->position = position;
        event->length = length;
        event->loss_count = loss_count;
        event->raw = raw;
        return event;
    }
    return NULL;
}
static int event_published(struct queued_event *event, uint64_t position) {
    return __atomic_load_n(&event->published, __ATOMIC_ACQUIRE) == position + 1;
}
static void publish_event(struct queued_event *event) {
    __atomic_store_n(&event->published, event->position + 1, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if (__atomic_load_n(&worker_sleeping, __ATOMIC_ACQUIRE))
        pthread_cond_signal(&event_ready);
}
static void release_event(struct queued_event *event, uint64_t position) {
    __atomic_store_n(&event->available, position + EVENT_QUEUE, __ATOMIC_RELEASE);
    __atomic_store_n(&queue_read, position + 1, __ATOMIC_RELEASE);
}
static void wait_for_worker(uint64_t deadline) {
    struct timespec wake = {
        .tv_sec = (time_t)(deadline / 1000),
        .tv_nsec = (long)(deadline % 1000) * 1000000
    };
    pthread_cond_timedwait(&event_ready, &wait_mutex, &wake);
}

static void wait_for_retry(void) {
    pthread_mutex_lock(&wait_mutex);
    uint64_t until = atomic_load(&retry_after);
    if (__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) {
        uint64_t stop = atomic_load(&stop_deadline);
        if (stop < until)
            until = stop;
    }
    wait_for_worker(until);
    pthread_mutex_unlock(&wait_mutex);
}

static int report_loss(void);
static void *send_worker(void *unused) {
    char message[EVENT_SIZE];
    uint64_t discard_until = 0;
    (void)unused;
    for (;;) {
        uint64_t position = atomic_load(&queue_read);
        uint64_t end = __atomic_load_n(&queue_write, __ATOMIC_ACQUIRE);
        struct queued_event *event = &events[position % EVENT_QUEUE];
        if (position == end && !report_loss() &&
            !__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) {
            wait_for_retry();
            continue;
        }
        if ((position == end || !event_published(event, position)) &&
            !__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) {
            pthread_mutex_lock(&wait_mutex);
            __atomic_store_n(&worker_sleeping, 1, __ATOMIC_RELEASE);
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            /* Recheck after advertising sleep. Producers never need this
             * mutex; the timeout bounds a publication racing the wait. */
            if (!event_published(event, position) &&
                !__atomic_load_n(&stopping, __ATOMIC_ACQUIRE))
                wait_for_worker(monotonic_milliseconds() + 10);
            __atomic_store_n(&worker_sleeping, 0, __ATOMIC_RELAXED);
            pthread_mutex_unlock(&wait_mutex);
            continue;
        }
        if (position == end ||
            (__atomic_load_n(&stopping, __ATOMIC_ACQUIRE) && monotonic_milliseconds() >= atomic_load(&stop_deadline))) {
            (void)report_loss();
            /* Unpublished reservations remain unavailable through shutdown.
             * This backend has no end-to-end final-count acknowledgement. */
            break;
        }
        if (!event_published(event, position)) {
            struct timespec pause = {0, 1000000};
            nanosleep(&pause, NULL);
            continue;
        }
        if (position < discard_until) {
            atomic_fetch_add(&lost, event->loss_count);
            release_event(event, position);
            continue;
        }
        if (!report_loss()) {
            wait_for_retry();
            continue;
        }
        size_t length = event->length;
        uint64_t loss_count = event->loss_count;
        if (event->raw) {
            const struct raw_event *copy = &event->payload.body;
            int header = snprintf(message, sizeof(message),
                "{\"protocol\":\"traffic-openssl-v1\",\"type\":\"data\","
                "\"connection\":\"%ld-%p-%llu\","
                "\"process_id\":\"%s\",\"direction\":\"%s\",\"local\":\"%s\","
                "\"client\":\"%s\",\"data_b64\":\"",
                (long)copy->pid, copy->ssl, (unsigned long long)copy->generation,
                copy->identity, copy->direction, copy->local, copy->peer);
            if (header < 0 || (size_t)header >= sizeof(message) ||
                length > sizeof(copy->bytes) ||
                4 * ((length + 2) / 3) + 2 > sizeof(message) - (size_t)header) {
                atomic_fetch_add(&lost, loss_count);
                release_event(event, position);
                continue;
            }
            size_t used = (size_t)header;
            used += encode_base64(message + used, copy->bytes, length);
            memcpy(message + used, "\"}", 2);
            length = used + 2;
        } else {
            memcpy(message, event->payload.data, length);
        }
        release_event(event, position);
        uint64_t deadline = monotonic_milliseconds() + 1000;
        int error;
        do {
            pthread_mutex_lock(&transport_mutex);
            error = transmit_event(message, length);
            pthread_mutex_unlock(&transport_mutex);
            if (event_socket < 0 || (error != EAGAIN && error != EWOULDBLOCK))
                break;
            struct pollfd writable = {event_socket, POLLOUT, 0};
            poll(&writable, 1, 5);
            if (__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) {
                uint64_t stop = atomic_load(&stop_deadline);
                if (stop < deadline)
                    deadline = stop;
            }
        } while (monotonic_milliseconds() < deadline);
        if (error) {
            atomic_store(&retry_after, monotonic_milliseconds() + 1000);
            atomic_store(&transport_errno, error);
            atomic_fetch_add(&lost, loss_count);
            /* Snapshot the queued tail. Retire each slot only after its
             * producer publishes it; later reservations stay in the queue. */
            discard_until = __atomic_load_n(&queue_write, __ATOMIC_ACQUIRE);
            __atomic_fetch_add(&transport_lost, loss_count, __ATOMIC_RELEASE);
        }
    }
    return NULL;
}
static void refresh_identity(void);
static void start_worker(void) {
    refresh_identity();
    for (size_t i = 0; i < EVENT_QUEUE; i++)
        events[i].available = i;
    pthread_mutex_lock(&wait_mutex);
    if (event_ready_initialized && !__atomic_load_n(&stopping, __ATOMIC_ACQUIRE) &&
        !pthread_create(&worker, NULL, send_worker, NULL))
        atomic_store(&worker_running, 1);
    pthread_mutex_unlock(&wait_mutex);
}
static int ensure_worker(void) {
    /* Creation happens before taking a connection mutex. A scheduling pause
     * inside pthread_create must not consume another TLS thread's lock budget. */
    pthread_once(&worker_once, start_worker);
    return atomic_load(&worker_running);
}
/* Control records share the same bounded reservation/publication protocol. */
static int send_event(const char *message, size_t length) {
    if (!destination[0] || !atomic_load(&worker_running) || length > EVENT_SIZE)
        return 0;
    struct queued_event *event = reserve_event(length, 0, 1);
    if (!event)
        return 0;
    memcpy(event->payload.data, message, length);
    publish_event(event);
    return 1;
}

static void refresh_identity(void) {
    FILE *file;
    char stat[4096], *end, *token, *saved;
    unsigned int i;
    pid_t pid = getpid();
    identity_pid = pid;
    identity[0] = 0;
    identity_len = 1;
    file = fopen("/proc/self/stat", "r");
    if (!file)
        return;
    end = fgets(stat, sizeof(stat), file);
    fclose(file);
    if (!end || !(end = strrchr(stat, ')')))
        return;
    token = strtok_r(end + 1, " ", &saved);
    for (i = 0; i < 19 && token; i++)
        token = strtok_r(NULL, " ", &saved);
    if (!token)
        return;
    int length = snprintf(identity, sizeof(identity), "%ld:%s", (long)pid, token);
    if (length >= 0 && (size_t)length < sizeof(identity))
        identity_len = (size_t)length + 1;
    else
        identity[0] = 0;
}

/* The worker owns loss formatting and transmission. A failed marker remains
 * pending, so later plaintext can never overtake an unreported gap. */
static int report_loss(void) {
    uint64_t retry = atomic_load(&retry_after);
    if (retry && monotonic_milliseconds() < retry)
        return atomic_load(&lost) == 0 && atomic_load(&contention_lost) == 0 &&
            atomic_load(&cooldown_lost) == 0 && atomic_load(&metadata_pending) == 0;
    uint64_t contention = atomic_exchange(&contention_lost, 0);
    uint64_t cooldown = atomic_exchange(&cooldown_lost, 0);
    uint64_t metadata = atomic_exchange(&metadata_pending, 0);
    atomic_fetch_add(&metadata_lost, metadata);
    atomic_fetch_add(&lost, contention + cooldown + metadata);
    uint64_t count = atomic_exchange(&lost, 0);
    if (!count)
        return 1;
    char message[512];
    int length = snprintf(message, sizeof(message),
        "{\"protocol\":\"traffic-openssl-v1\",\"type\":\"loss\","
        "\"process_id\":\"%s\",\"count\":%llu,"
        "\"message\":\"recent_lock=%llu recent_cooldown=%llu cumulative_queue=%llu cumulative_metadata=%llu cumulative_transport=%llu pending=%llu errno=%d\"}",
        identity, (unsigned long long)count, (unsigned long long)contention,
        (unsigned long long)cooldown, (unsigned long long)atomic_load(&queue_lost),
        (unsigned long long)atomic_load(&metadata_lost),
        (unsigned long long)atomic_load(&transport_lost),
        (unsigned long long)queue_length(), atomic_load(&transport_errno));
    int error = EOVERFLOW;
    if (length >= 0 && (size_t)length < sizeof(message)) {
        pthread_mutex_lock(&transport_mutex);
        error = transmit_event(message, (size_t)length);
        pthread_mutex_unlock(&transport_mutex);
    }
    if (!error) {
        atomic_fetch_add(&metadata_epoch, 1);
        atomic_store(&retry_after, 0);
        return 1;
    }
    atomic_fetch_add(&lost, count);
    atomic_store(&transport_errno, error);
    atomic_store(&retry_after, monotonic_milliseconds() + 1000);
    return 0;
}

static size_t connection_home(uint64_t hash) {
    return (hash / CONNECTION_STRIPES) % CONNECTION_WIDTH;
}

/* Callers hold the mutex for this connection's stripe. */
static struct connection *find_connection(void *ssl, int create) {
    uint64_t hash = connection_hash(ssl);
    struct connection *stripe = connections[hash % CONNECTION_STRIPES];
    size_t initial = connection_home(hash);
    for (size_t step = 0; step < CONNECTION_WIDTH; step++) {
        struct connection *entry = &stripe[(initial + step) % CONNECTION_WIDTH];
        if (entry->ssl == ssl)
            return entry;
        if (!entry->ssl) {
            if (!create)
                return NULL;
            entry->ssl = ssl;
            entry->fd = -1;
            entry->generation = atomic_fetch_add(&sequence, 1) + 1;
            return entry;
        }
    }
    return NULL;
}

static void remove_connection(struct connection *entry) {
    struct connection *stripe = connections[connection_hash(entry->ssl) % CONNECTION_STRIPES];
    size_t hole = (size_t)(entry - stripe);
    size_t i = (hole + 1) % CONNECTION_WIDTH;
    for (size_t scanned = 0; scanned < CONNECTION_WIDTH - 1 && stripe[i].ssl;
         scanned++, i = (i + 1) % CONNECTION_WIDTH) {
        size_t home = connection_home(connection_hash(stripe[i].ssl));
        /* Move only entries whose probe path crosses the hole. */
        if ((hole + CONNECTION_WIDTH - home) % CONNECTION_WIDTH <
            (i + CONNECTION_WIDTH - home) % CONNECTION_WIDTH) {
            stripe[hole] = stripe[i];
            hole = i;
        }
    }
    stripe[hole].ssl = NULL;
}

/* Return the formatted length including the terminator. */
static size_t endpoint(int fd, int peer, char *output, size_t capacity) {
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    char host[INET6_ADDRSTRLEN];
    int result = peer ? getpeername(fd, (struct sockaddr *)&address, &length)
                      : getsockname(fd, (struct sockaddr *)&address, &length);
    if (result)
        return 0;
    int written;
    if (address.ss_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *inet = (const struct sockaddr_in *)&address;
        if (!inet_ntop(AF_INET, &inet->sin_addr, host, sizeof(host)))
            return 0;
        written = snprintf(output, capacity, "%s:%u", host,
                           (unsigned)ntohs(inet->sin_port));
    } else if (address.ss_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *inet = (const struct sockaddr_in6 *)&address;
        if (!inet_ntop(AF_INET6, &inet->sin6_addr, host, sizeof(host)))
            return 0;
        unsigned port = ntohs(inet->sin6_port);
        unsigned scope = inet->sin6_scope_id;
        char zone[IF_NAMESIZE];
        if (!scope)
            written = snprintf(output, capacity, "[%s]:%u", host, port);
        else if ((IN6_IS_ADDR_LINKLOCAL(&inet->sin6_addr) ||
                  IN6_IS_ADDR_MC_LINKLOCAL(&inet->sin6_addr)) &&
                 if_indextoname(scope, zone))
            written = snprintf(output, capacity, "[%s%%%s]:%u", host, zone, port);
        else
            written = snprintf(output, capacity, "[%s%%%u]:%u", host, scope, port);
    } else {
        return 0;
    }
    return written >= 0 && (size_t)written < capacity ? (size_t)written + 1 : 0;
}

static size_t encode_base64(char *output, const unsigned char *input,
                            size_t length) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, used = 0;
    for (i = 0; i < length; i += 3) {
        uint32_t value = (uint32_t)input[i] << 16;
        if (i + 1 < length)
            value |= (uint32_t)input[i + 1] << 8;
        if (i + 2 < length)
            value |= input[i + 2];
        output[used++] = alphabet[(value >> 18) & 63];
        output[used++] = alphabet[(value >> 12) & 63];
        output[used++] = i + 1 < length ? alphabet[(value >> 6) & 63] : '=';
        output[used++] = i + 2 < length ? alphabet[value & 63] : '=';
    }
    return used;
}

static void emit_data(void *ssl, const void *buffer, size_t length,
                      const char *direction, size_t direction_len) {
    const unsigned char *bytes = buffer;
    struct connection *connection;
    int fd;
    if (!destination[0] || !length)
        return;
    if (!ensure_worker()) {
        atomic_fetch_add(&lost, 1);
        return;
    }
    uint64_t retry = atomic_load(&retry_after);
    if (retry && monotonic_milliseconds() < retry) {
        atomic_fetch_add(&cooldown_lost, 1);
        return;
    }
    fd = next_get_fd ? next_get_fd(ssl) : -1;
    pthread_mutex_t *mutex = connection_lock(ssl);
    if (!acquire_event_lock(mutex)) {
        atomic_fetch_add(&contention_lost, 1);
        return;
    }
    if (__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) {
        atomic_fetch_add(&lost, 1);
        atomic_fetch_add(&queue_lost, 1);
        pthread_mutex_unlock(mutex);
        return;
    }
    connection = find_connection(ssl, 1);
    if (!connection || fd < 0) {
        atomic_fetch_add(&lost, 1);
        atomic_fetch_add(&metadata_lost, 1);
        pthread_mutex_unlock(mutex);
        return;
    }
    uint64_t epoch = atomic_load(&metadata_epoch);
    if (connection->fd != fd || connection->epoch != epoch) {
        char local[128], peer[128];
        /* Numeric endpoint lookup still enters libc and the kernel. Resolve
         * outside the connection mutex so a new connection cannot exclude other
         * application threads for the whole syscall or a scheduling pause. */
        pthread_mutex_unlock(mutex);
        size_t local_len = endpoint(fd, 0, local, sizeof(local));
        size_t peer_len = local_len ? endpoint(fd, 1, peer, sizeof(peer)) : 0;
        if (!peer_len) {
            atomic_fetch_add(&metadata_pending, 1);
            return;
        }
        if (!acquire_event_lock(mutex)) {
            atomic_fetch_add(&contention_lost, 1);
            return;
        }
        connection = find_connection(ssl, 1);
        if (!connection) {
            atomic_fetch_add(&lost, 1);
            atomic_fetch_add(&metadata_lost, 1);
            pthread_mutex_unlock(mutex);
            return;
        }
        if (connection->fd >= 0 &&
            (connection->epoch != epoch || connection->fd != fd ||
             strcmp(connection->local, local) ||
             strcmp(connection->peer, peer)))
            connection->generation = atomic_fetch_add(&sequence, 1) + 1;
        memcpy(connection->local, local, local_len);
        memcpy(connection->peer, peer, peer_len);
        connection->local_len = (uint8_t)local_len;
        connection->peer_len = (uint8_t)peer_len;
        connection->fd = fd;
        connection->epoch = epoch;
    }
    struct connection snapshot = *connection;
    pthread_mutex_unlock(mutex);
    while (length) {
        size_t chunk = length < CHUNK_SIZE ? length : CHUNK_SIZE;
        struct queued_event *event = reserve_event(chunk, 1, 1);
        if (!event) {
            atomic_fetch_add(&lost, 1);
            atomic_fetch_add(&queue_lost, 1);
            break;
        }
        struct raw_event *body = &event->payload.body;
        /* The connection snapshot and reserved slot have independent lifetimes;
         * copying a large TLS call never holds a metadata mutex. */
        memcpy(body->bytes, bytes, chunk);
        memcpy(body->local, snapshot.local, snapshot.local_len);
        memcpy(body->peer, snapshot.peer, snapshot.peer_len);
        memcpy(body->identity, identity, identity_len);
        memcpy(body->direction, direction, direction_len);
        body->ssl = ssl;
        body->pid = identity_pid;
        body->generation = snapshot.generation;
        publish_event(event);
        bytes += chunk;
        length -= chunk;
    }
}

void *SSL_new(void *context) {
    void *ssl;
    int saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_new) {
        errno = ENOSYS;
        return NULL;
    }
    ssl = next_new(context);
    saved_errno = errno;
    if (ssl && destination[0]) {
        (void)ensure_worker();
        pthread_mutex_t *mutex = connection_lock(ssl);
        if (!pthread_mutex_trylock(mutex)) {
            (void)find_connection(ssl, 1);
            pthread_mutex_unlock(mutex);
        }
    }
    errno = saved_errno;
    return ssl;
}

void SSL_free(void *ssl) {
    int saved_errno = errno;
    pthread_once(&initialize_once, initialize);
    if (ssl && destination[0]) {
        (void)ensure_worker();
        pthread_mutex_t *mutex = connection_lock(ssl);
        uint64_t generation = 0;
        pthread_mutex_lock(mutex);
        struct connection *connection = find_connection(ssl, 0);
        if (connection) {
            generation = connection->generation;
            remove_connection(connection);
        }
        pthread_mutex_unlock(mutex);
        if (connection) {
            char message[384];
            int length = snprintf(
                message, sizeof(message),
                "{\"protocol\":\"traffic-openssl-v1\",\"type\":\"close\","
                "\"process_id\":\"%s\",\"connection\":\"%ld-%p-%llu\"}",
                identity, (long)identity_pid, ssl,
                (unsigned long long)generation);
            if (length < 0 || (size_t)length >= sizeof(message) ||
                !send_event(message, (size_t)length))
                atomic_fetch_add(&lost, 1);
        }
    }
    errno = saved_errno;
    if (next_free)
        next_free(ssl);
}

int SSL_set_fd(void *ssl, int fd) {
    int result, saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_set_fd) {
        errno = ENOSYS;
        return 0;
    }
    result = next_set_fd(ssl, fd);
    saved_errno = errno;
    if (result == 1 && destination[0]) {
        pthread_mutex_t *mutex = connection_lock(ssl);
        if (acquire_event_lock(mutex)) {
            struct connection *connection = find_connection(ssl, 1);
            if (connection) {
                connection->fd = -1;
                connection->generation = atomic_fetch_add(&sequence, 1) + 1;
            }
            pthread_mutex_unlock(mutex);
        } else
            atomic_fetch_add(&metadata_epoch, 1);
    }
    errno = saved_errno;
    return result;
}

int SSL_read(void *ssl, void *buffer, int length) {
    int result, saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_read) {
        errno = ENOSYS;
        return -1;
    }
    call_depth++;
    result = next_read(ssl, buffer, length);
    saved_errno = errno;
    if (--call_depth == 0 && result > 0)
        emit_data(ssl, buffer, (size_t)result, "read", sizeof("read"));
    errno = saved_errno;
    return result;
}

int SSL_write(void *ssl, const void *buffer, int length) {
    int result, saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_write) {
        errno = ENOSYS;
        return -1;
    }
    call_depth++;
    result = next_write(ssl, buffer, length);
    saved_errno = errno;
    if (--call_depth == 0 && result > 0)
        emit_data(ssl, buffer, (size_t)result, "write", sizeof("write"));
    errno = saved_errno;
    return result;
}

int SSL_read_ex(void *ssl, void *buffer, size_t length, size_t *read_bytes) {
    int result, saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_read_ex) {
        errno = ENOSYS;
        return 0;
    }
    call_depth++;
    result = next_read_ex(ssl, buffer, length, read_bytes);
    saved_errno = errno;
    if (--call_depth == 0 && result == 1 && read_bytes)
        emit_data(ssl, buffer, *read_bytes, "read", sizeof("read"));
    errno = saved_errno;
    return result;
}

int SSL_write_ex(void *ssl, const void *buffer, size_t length,
                 size_t *written_bytes) {
    int result, saved_errno;
    pthread_once(&initialize_once, initialize);
    if (!next_write_ex) {
        errno = ENOSYS;
        return 0;
    }
    call_depth++;
    result = next_write_ex(ssl, buffer, length, written_bytes);
    saved_errno = errno;
    if (--call_depth == 0 && result == 1 && written_bytes)
        emit_data(ssl, buffer, *written_bytes, "write", sizeof("write"));
    errno = saved_errno;
    return result;
}

__attribute__((destructor)) static void shutdown_events(void) {
    pthread_mutex_lock(&wait_mutex);
    atomic_store(&stop_deadline, monotonic_milliseconds() + 500);
    __atomic_store_n(&stopping, 1, __ATOMIC_RELEASE);
    if (event_ready_initialized)
        pthread_cond_signal(&event_ready);
    pthread_mutex_unlock(&wait_mutex);
    if (atomic_load(&worker_running)) {
        pthread_join(worker, NULL);
        atomic_store(&worker_running, 0);
    }
    if (event_socket >= 0) {
        close(event_socket);
        event_socket = -1;
    }
}
