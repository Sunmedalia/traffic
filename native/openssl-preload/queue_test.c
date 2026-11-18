/* Exercise reservation/publication and failed-transport retirement without
 * OpenSSL, root, packet capture or changes to any system service. */
#include "traffic_openssl.c"
#include <assert.h>
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

int main(void) {
    char directory[] = "/tmp/traffic-queue-XXXXXX";
    assert(mkdtemp(directory));
    assert(snprintf(destination, sizeof(destination), "%s/events", directory) > 0);
    int fd = receiver(destination);

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
    pthread_mutex_lock(&connection_mutex[0]);
    assert(send_event("bad", 3));
    struct queued_event *pending = reserve();
    pthread_mutex_unlock(&connection_mutex[0]);
    uint64_t deadline = monotonic_milliseconds() + 2000;
    int failed = 0;
    while (monotonic_milliseconds() < deadline) {
        pthread_mutex_lock(&connection_mutex[0]);
        failed = __atomic_load_n(&transport_lost, __ATOMIC_ACQUIRE) > 0;
        if (failed) {
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
    uint64_t wait_queued = monotonic_milliseconds() + 1000;
    while (queue_length() > 0 && monotonic_milliseconds() < wait_queued)
        usleep(1000);
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

    pthread_mutex_lock(&connection_mutex[0]);
    atomic_store(&stop_deadline, monotonic_milliseconds() + 500);
    __atomic_store_n(&stopping, 1, __ATOMIC_RELEASE);
    pthread_cond_signal(&event_ready);
    pthread_mutex_unlock(&connection_mutex[0]);
    assert(pthread_join(worker, NULL) == 0);
    atomic_store(&worker_running, 0);
    if (event_socket >= 0) close(event_socket);
    event_socket = -1;
    close(fd);
    assert(unlink(destination) == 0);
    assert(rmdir(directory) == 0);
    return 0;
}
