/* Exercise reservation/publication and failed-transport retirement without
 * OpenSSL, root, packet capture or changes to any system service. */
#include "traffic_openssl.c"
#include <assert.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>

static int receiver(const char *path) {
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    assert(strlen(path) < sizeof(address.sun_path));
    strcpy(address.sun_path, path);
    assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    struct timeval timeout = {0, 50000};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}

static void expect_message(int fd, const char *expected) {
    char data[128];
    ssize_t n = recv(fd, data, sizeof(data) - 1, 0);
    assert(n >= 0);
    data[n] = 0;
    assert(!strcmp(data, expected));
}

static struct queued_event *reserve(void) {
    struct queued_event *event = reserve_event(3, 0, 1);
    assert(event);
    return event;
}

static void publish(struct queued_event *event, const char *data) {
    memcpy(event->payload.data, data, 3);
    publish_event(event);
}

static void *producer(void *argument) {
    int number = (int)(intptr_t)argument;
    for (int i = 0; i < 200; i++) {
        char message[32];
        int length = snprintf(message, sizeof(message), "%d:%d", number, i);
        struct queued_event *event = NULL;
        while (!event) {
            event = reserve_event((size_t)length, 0, 1);
            if (!event) usleep(100);
        }
        if (i % 7 == 0) usleep(100);
        memcpy(event->payload.data, message, (size_t)length);
        publish_event(event);
    }
    return NULL;
}

static void test_connection_deletion(void) {
    const size_t stripe = 3, home = CONNECTION_WIDTH - 2;
    void *keys[CONNECTION_WIDTH];
    void *anchor = NULL;
    size_t count = 0;
    for (uintptr_t address = 16; count < CONNECTION_WIDTH || !anchor; address += 16) {
        void *ssl = (void *)address;
        uint64_t hash = connection_hash(ssl);
        if (hash % CONNECTION_STRIPES != stripe)
            continue;
        if (connection_home(hash) == home && count < CONNECTION_WIDTH)
            keys[count++] = ssl;
        if (connection_home(hash) == home + 1)
            anchor = ssl;
    }

    pthread_mutex_lock(&connection_mutex[stripe]);
    struct connection *first = find_connection(keys[0], 1);
    struct connection *fixed = find_connection(anchor, 1);
    assert(first == &connections[stripe][home]);
    assert(fixed == first + 1);
    uint64_t generations[CONNECTION_WIDTH];
    for (size_t i = 1; i < CONNECTION_WIDTH - 1; i++) {
        struct connection *entry = find_connection(keys[i], 1);
        assert(entry == &connections[stripe][(home + i + 1) % CONNECTION_WIDTH]);
        entry->fd = (int)i;
        generations[i] = entry->generation;
    }
    assert(find_connection(keys[CONNECTION_WIDTH - 1], 1) == NULL);

    remove_connection(first);
    assert(find_connection(keys[0], 0) == NULL);
    assert(find_connection(anchor, 0) == fixed);
    for (size_t i = 1; i < CONNECTION_WIDTH - 1; i++) {
        struct connection *entry = find_connection(keys[i], 0);
        assert(entry && entry->fd == (int)i && entry->generation == generations[i]);
    }
    struct connection *replacement = find_connection(keys[CONNECTION_WIDTH - 1], 1);
    assert(replacement && replacement->fd == -1);
    assert(find_connection(keys[0], 1) == NULL);
    for (size_t i = 1; i < CONNECTION_WIDTH; i++) {
        struct connection *entry = find_connection(keys[i], 0);
        assert(entry);
        remove_connection(entry);
    }
    remove_connection(find_connection(anchor, 0));
    for (size_t i = 0; i < CONNECTION_WIDTH; i++)
        assert(connections[stripe][i].ssl == NULL);
    pthread_mutex_unlock(&connection_mutex[stripe]);
}

static void test_raw_event_boundary(int fd) {
    struct queued_event *event = reserve_event(CHUNK_SIZE, 1, 1);
    assert(event);
    memset(&event->payload.body, 0, sizeof(event->payload.body));
    strcpy(event->payload.body.direction, "read");
    publish_event(event);
    char message[EVENT_SIZE];
    ssize_t n = recv(fd, message, sizeof(message) - 1, 0);
    assert(n > 0);
    message[n] = 0;
    const char *payload = strstr(message, "\"data_b64\":\"");
    assert(payload);
    payload += strlen("\"data_b64\":\"");
    assert(strspn(payload, "A") == CHUNK_SIZE * 4 / 3);
    assert(!strcmp(payload + CHUNK_SIZE * 4 / 3, "\"}"));

    /* Reject an invalid raw record and keep the next queue item deliverable. */
    event = reserve_event(CHUNK_SIZE + 1, 1, 1);
    assert(event);
    memset(&event->payload.body, 0, sizeof(event->payload.body));
    publish_event(event);
    assert(send_event("next", 4));
    n = recv(fd, message, sizeof(message) - 1, 0);
    assert(n > 0);
    message[n] = 0;
    assert(strstr(message, "\"type\":\"loss\"") && strstr(message, "\"count\":1"));
    expect_message(fd, "next");
}

static void test_endpoints(void) {
    struct sockaddr_in server4 = { .sin_family = AF_INET };
    server4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct sockaddr_in6 server6 = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
    for (int i = 0; i < 2; i++) {
        int family = i ? AF_INET6 : AF_INET;
        struct sockaddr *address = i ? (struct sockaddr *)&server6 : (struct sockaddr *)&server4;
        socklen_t length = i ? sizeof(server6) : sizeof(server4);
        int server = socket(family, SOCK_DGRAM, 0);
        if (i && server < 0 && errno == EAFNOSUPPORT)
            continue;
        assert(server >= 0);
        if (i && bind(server, address, length) < 0) {
            assert(errno == EADDRNOTAVAIL);
            close(server);
            continue;
        }
        if (!i)
            assert(bind(server, address, length) == 0);
        assert(getsockname(server, address, &length) == 0);
        int client = socket(family, SOCK_DGRAM, 0);
        assert(client >= 0 && connect(client, address, length) == 0);
        char local[128], peer[128], tiny[4];
        size_t n = endpoint(server, 0, local, sizeof(local));
        assert(n && n == strlen(local) + 1);
        assert(endpoint(client, 1, peer, sizeof(peer)) == n && !strcmp(local, peer));
        assert(!strncmp(local, i ? "[::1]:" : "127.0.0.1:", i ? 6 : 10));
        unsigned port = ntohs(i ? server6.sin6_port : server4.sin_port);
        assert(strtoul(strrchr(local, ':') + 1, NULL, 10) == port);
        assert(!endpoint(client, 1, tiny, sizeof(tiny)));
        close(client);
        close(server);
    }
}

/* A fork in a process that never selected a destination must not fault in
 * the event queue: one page per slot with the full reset. The child must still
 * be able to become a target afterwards. */
static void test_inert_fork(int fd) {
    char selected[sizeof(destination)];
    assert(!atomic_load(&worker_running) && queue_write == 0);
    strcpy(selected, destination);
    destination[0] = 0;
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        struct rusage usage;
        assert(getrusage(RUSAGE_SELF, &usage) == 0);
        if (usage.ru_minflt >= EVENT_QUEUE / 2)
            _exit(2);
        strcpy(destination, selected);
        assert(ensure_worker());
        assert(send_event("idle", 4));
        exit(0);
    }
    strcpy(destination, selected);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
    expect_message(fd, "idle");
}

static void test_monotonic_wait(void) {
    assert(event_ready_initialized);
    pthread_mutex_lock(&wait_mutex);
    uint64_t deadline = monotonic_milliseconds() + 25;
    wait_for_worker(deadline);
    assert(monotonic_milliseconds() >= deadline);
    pthread_mutex_unlock(&wait_mutex);
}

int main(void) {
    test_monotonic_wait();
    test_connection_deletion();
    test_endpoints();
    char directory[] = "/tmp/traffic-queue-XXXXXX";
    assert(mkdtemp(directory));
    assert(snprintf(destination, sizeof(destination), "%s/events", directory) > 0);
    int fd = receiver(destination);
    if (!getenv("TRAFFIC_TEST_SKIP_FORK"))
        test_inert_fork(fd);

    assert(ensure_worker());
    pthread_mutex_lock(&connection_mutex[0]);
    struct queued_event *first = reserve();
    assert(send_event("two", 3));
    for (int i = 2; i < EVENT_QUEUE; i++)
        assert(send_event("buf", 3));
    assert(reserve_event(3, 0, 1) == NULL);
    pthread_mutex_unlock(&connection_mutex[0]);
    /* A ready second slot must never pass an unpublished first slot. */
    char data[128];
    assert(recv(fd, data, sizeof(data), 0) < 0 &&
           (errno == EAGAIN || errno == EWOULDBLOCK));
    /* A producer paused while holding its metadata mutex must not prevent
     * the worker from draining already-published queue entries. */
    pthread_mutex_lock(&connection_mutex[0]);
    publish(first, "one");
    expect_message(fd, "one");
    expect_message(fd, "two");
    for (int i = 2; i < EVENT_QUEUE; i++)
        expect_message(fd, "buf");
    pthread_mutex_unlock(&connection_mutex[0]);

    test_raw_event_boundary(fd);

    /* Repeated wraparound with out-of-lock publication and four producers. */
    pthread_t producers[4];
    int received[4] = {0};
    struct timeval longer_timeout = {2, 0};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &longer_timeout, sizeof(longer_timeout)) == 0);
    for (int i = 0; i < 4; i++)
        assert(pthread_create(&producers[i], NULL, producer, (void *)(intptr_t)i) == 0);
    for (int i = 0; i < 800; i++) {
        ssize_t length = recv(fd, data, sizeof(data) - 1, 0);
        assert(length > 0);
        data[length] = 0;
        int number, sequence_number;
        assert(sscanf(data, "%d:%d", &number, &sequence_number) == 2);
        assert(number >= 0 && number < 4);
        assert(sequence_number == received[number]++);
    }
    for (int i = 0; i < 4; i++) {
        assert(pthread_join(producers[i], NULL) == 0);
        assert(received[i] == 200);
    }
    /* TSan cannot restart threads after a multi-threaded fork. The normal
     * test always covers this path; sanitizer runs may skip only this block. */
    if (!getenv("TRAFFIC_TEST_SKIP_FORK")) {
        /* A child discards inherited reservations and restarts its own worker;
         * the parent's outstanding reservation and worker remain valid. */
        pthread_mutex_lock(&connection_mutex[0]);
        struct queued_event *inherited = reserve();
        pthread_mutex_unlock(&connection_mutex[0]);
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            test_monotonic_wait();
            assert(ensure_worker());
            assert(send_event("kid", 3));
            exit(0);
        }
        expect_message(fd, "kid");
        int status;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        publish(inherited, "par");
        expect_message(fd, "par");
    }

    close(fd);
    assert(unlink(destination) == 0);
    /* Reserve both slots before publishing "bad". The worker snapshots the
     * queue tail when the transmission fails; a slot reserved after that
     * snapshot is delivered normally instead of being counted as lost, so
     * publishing first would race the worker. */
    pthread_mutex_lock(&connection_mutex[0]);
    struct queued_event *bad = reserve();
    struct queued_event *pending = reserve();
    publish(bad, "bad");
    pthread_mutex_unlock(&connection_mutex[0]);
    uint64_t deadline = monotonic_milliseconds() + 2000;
    uint64_t failed_retry = 0;
    int failed = 0;
    while (monotonic_milliseconds() < deadline) {
        pthread_mutex_lock(&connection_mutex[0]);
        failed = __atomic_load_n(&transport_lost, __ATOMIC_ACQUIRE) > 0;
        if (failed) {
            failed_retry = atomic_load(&retry_after);
            assert(failed_retry != 0 && atomic_load(&transport_errno) != 0);
            /* Failed transmission must not free an unpublished tail slot. */
            assert(queue_length() == 1);
            assert(&events[atomic_load(&queue_read) % EVENT_QUEUE] == pending);
            assert(send_event("new", 3));
        }
        pthread_mutex_unlock(&connection_mutex[0]);
        if (failed)
            break;
        usleep(1000);
    }
    assert(failed);
    fd = receiver(destination);
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &longer_timeout, sizeof(longer_timeout)) == 0);
    publish(pending, "old");
    ssize_t loss_length = recv(fd, data, sizeof(data) - 1, 0);
    assert(loss_length > 0);
    assert(monotonic_milliseconds() >= failed_retry);
    data[loss_length] = 0;
    assert(strstr(data, "\"type\":\"loss\""));
    assert(strstr(data, "\"count\":2"));
    expect_message(fd, "new");
    struct timeval short_timeout = {0, 50000};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &short_timeout, sizeof(short_timeout)) == 0);
    assert(recv(fd, data, sizeof(data), 0) < 0 &&
           (errno == EAGAIN || errno == EWOULDBLOCK));

    /* Collector read-shutdown stops new datagrams while preserving queued ones,
     * and resets the sender socket on EPIPE so a later collector can rebind. */
    assert(send_event("pre", 3));
    struct timeval poll_timeout = {0, 10000};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &poll_timeout, sizeof(poll_timeout)) == 0);
    /* The worker releases a slot before it sends, so an empty queue does not
     * mean "pre" has been delivered. Wait until it is in the receive queue;
     * shutting down earlier would discard or refuse it. */
    char peeked[8];
    uint64_t wait_queued = monotonic_milliseconds() + 1000;
    while (recv(fd, peeked, sizeof(peeked), MSG_PEEK) <= 0 &&
           monotonic_milliseconds() < wait_queued)
        ;
    assert(recv(fd, peeked, sizeof(peeked), MSG_PEEK) == 3);
    assert(shutdown(fd, SHUT_RD) == 0);
    assert(unlink(destination) == 0);
    expect_message(fd, "pre");
    assert(recv(fd, data, sizeof(data), 0) == 0);
    close(fd);

    uint64_t prior_transport_lost = __atomic_load_n(&transport_lost, __ATOMIC_ACQUIRE);
    assert(send_event("epipe", 5));
    deadline = monotonic_milliseconds() + 2000;
    while (__atomic_load_n(&transport_lost, __ATOMIC_ACQUIRE) == prior_transport_lost &&
           monotonic_milliseconds() < deadline)
        usleep(1000);
    assert(__atomic_load_n(&transport_lost, __ATOMIC_ACQUIRE) > prior_transport_lost);

    fd = receiver(destination);
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &longer_timeout, sizeof(longer_timeout)) == 0);
    usleep(1050000); /* wait past the 1s transport retry cooldown */
    assert(send_event("rec", 3));
    loss_length = recv(fd, data, sizeof(data) - 1, 0);
    assert(loss_length > 0);
    data[loss_length] = 0;
    assert(strstr(data, "\"type\":\"loss\""));
    expect_message(fd, "rec");

    deadline = monotonic_milliseconds() + 1000;
    while (!atomic_load(&worker_sleeping) && monotonic_milliseconds() < deadline)
        usleep(1000);
    assert(atomic_load(&worker_sleeping));
    shutdown_events();
    assert(!atomic_load(&worker_running) && event_socket == -1);
    close(fd);
    assert(unlink(destination) == 0);
    assert(rmdir(directory) == 0);
    return 0;
}
