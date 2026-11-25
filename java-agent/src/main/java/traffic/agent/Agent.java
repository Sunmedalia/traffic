package traffic.agent;

import static net.bytebuddy.matcher.ElementMatchers.*;

import java.io.*;
import java.lang.instrument.Instrumentation;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.net.*;
import java.nio.*;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import net.bytebuddy.agent.builder.*;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.DynamicType;

public final class Agent {
  public static volatile boolean active;
  private static volatile boolean running;
  private static final AtomicLong epoch = new AtomicLong();
  private static volatile AtomicInteger inFlight = new AtomicInteger();
  // Events and bytes are both bounded: a burst of small TLS records may use many
  // slots, while large records are limited by bytes held in the target heap.
  static final int QUEUE_EVENTS = 4096;
  static final long QUEUE_BYTES = 16L << 20;
  // The collector reads one JSON line of at most 128 KiB; base64 of a 64 KiB
  // chunk plus metadata stays below that.
  static final int CHUNK = 65536;
  static final int CALL_BUDGET = 1024 * 1024;
  static final int BATCH = 64;
  public static final ArrayBlockingQueue<Event> queue = new ArrayBlockingQueue<>(QUEUE_EVENTS);
  static final AtomicLong queuedBytes = new AtomicLong();
  public static final ThreadLocal<Boolean> inside = ThreadLocal.withInitial(() -> false);
  public static final AtomicLong serial = new AtomicLong();
  public static final AtomicLong dropped = new AtomicLong();
  private static volatile Set<Integer> selectedPorts = Collections.emptySet();
  private static volatile boolean protocolV2;

  /**
   * Per-connection state, created once when a channel is first seen. A channel
   * on a port that is not captured maps to {@link #IGNORED}, so later I/O on it
   * costs one map lookup instead of getLocalAddress() every call.
   */
  static final class ConnInfo {
    static final ConnInfo IGNORED = new ConnInfo(null, null, null, 0);
    final String id;
    final String client;
    final String local;
    final int port;
    // Set when an event of this connection was lost; the next event that is
    // queued for the same connection carries the incomplete marker.
    final AtomicBoolean gap = new AtomicBoolean();

    ConnInfo(String id, String client, String local, int port) {
      this.id = id;
      this.client = client;
      this.local = local;
      this.port = port;
    }
  }

  /**
   * Weak-keyed connection table split into independently locked segments, so
   * TLS calls on different connections rarely contend. Keys are SocketChannel
   * objects, which use identity equality; an entry disappears with its channel.
   */
  static final class ConnectionTable {
    private static final int SEGMENTS = 64;
    @SuppressWarnings("unchecked")
    private final WeakHashMap<SocketChannel, ConnInfo>[] segments = new WeakHashMap[SEGMENTS];

    ConnectionTable() {
      for (int i = 0; i < SEGMENTS; i++) segments[i] = new WeakHashMap<>();
    }

    private WeakHashMap<SocketChannel, ConnInfo> segment(SocketChannel channel) {
      int h = System.identityHashCode(channel);
      return segments[(h ^ (h >>> 16)) & (SEGMENTS - 1)];
    }

    ConnInfo get(SocketChannel channel) {
      WeakHashMap<SocketChannel, ConnInfo> segment = segment(channel);
      synchronized (segment) {
        return segment.get(channel);
      }
    }

    /** Stores a connection, numbering it under the segment lock; returns the winner. */
    ConnInfo add(SocketChannel channel, String client, String local, int port) {
      WeakHashMap<SocketChannel, ConnInfo> segment = segment(channel);
      synchronized (segment) {
        ConnInfo existing = segment.get(channel);
        if (existing != null)
          return existing;
        ConnInfo info = new ConnInfo(Long.toString(serial.incrementAndGet()), client, local, port);
        segment.put(channel, info);
        return info;
      }
    }

    ConnInfo ignore(SocketChannel channel) {
      WeakHashMap<SocketChannel, ConnInfo> segment = segment(channel);
      synchronized (segment) {
        ConnInfo existing = segment.get(channel);
        if (existing != null)
          return existing;
        segment.put(channel, ConnInfo.IGNORED);
        return ConnInfo.IGNORED;
      }
    }

    void clear() {
      for (WeakHashMap<SocketChannel, ConnInfo> segment : segments) {
        synchronized (segment) {
          segment.clear();
        }
      }
    }

    int size() {
      int size = 0;
      for (WeakHashMap<SocketChannel, ConnInfo> segment : segments) {
        synchronized (segment) {
          size += segment.size();
        }
      }
      return size;
    }
  }

  static final ConnectionTable connections = new ConnectionTable();

  // The agent is compiled for Java 8 so it can attach to JDK 8 through 21 targets.
  // getIOChannel() is resolved once per class into a MethodHandle typed
  // (Object)SocketChannel, replacing a reflective Method.invoke per TLS call.
  private static final ClassValue<MethodHandle> ioChannel = new ClassValue<MethodHandle>() {
    @Override
    protected MethodHandle computeValue(Class<?> type) {
      try {
        return MethodHandles.publicLookup()
            .unreflect(type.getMethod("getIOChannel"))
            .asType(MethodType.methodType(SocketChannel.class, Object.class));
      } catch (ReflectiveOperationException e) {
        throw new IllegalStateException(e);
      }
    }
  };
  private static ResettableClassFileTransformer transformer;
  private static Instrumentation instrumentation;

  public static final class Event {
    private final String connection;
    private final String client;
    private final String local;
    private final int port;
    private final byte[] data;
    private final boolean read;
    private final boolean incomplete;

    public Event(String connection, String client, String local, int port, byte[] data,
        boolean read, boolean incomplete) {
      this.connection = connection;
      this.client = client;
      this.local = local;
      this.port = port;
      this.data = data;
      this.read = read;
      this.incomplete = incomplete;
    }

    public String connection() {
      return connection;
    }

    public String client() {
      return client;
    }

    public String local() {
      return local;
    }

    public int port() {
      return port;
    }

    public byte[] data() {
      return data;
    }

    public boolean read() {
      return read;
    }

    public boolean incomplete() {
      return incomplete;
    }
  }

  /** Buffer positions at method entry: one buffer without an array, or a gathered set. */
  public static final class Saved {
    private final ByteBuffer buffer;
    private final int position;
    private final ByteBuffer[] buffers;
    private final int[] positions;
    private final Object channel;
    private final long epoch;
    private final AtomicInteger inFlight;

    Saved(ByteBuffer buffer, int position, ByteBuffer[] buffers, int[] positions, Object channel,
        long epoch, AtomicInteger inFlight) {
      this.buffer = buffer;
      this.position = position;
      this.buffers = buffers;
      this.positions = positions;
      this.channel = channel;
      this.epoch = epoch;
      this.inFlight = inFlight;
    }

    public Object channel() {
      return channel;
    }

    public long epoch() {
      return epoch;
    }

    public AtomicInteger inFlight() {
      return inFlight;
    }

    /** True when no buffer position moved, so the call transferred nothing. */
    boolean unchanged() {
      if (buffers == null)
        return buffer.position() == position;
      for (int i = 0; i < buffers.length; i++)
        if (buffers[i].position() != positions[i])
          return false;
      return true;
    }
  }

  /** Applies the I/O advice; shared by agentmain and the instrumentation tests. */
  static DynamicType.Builder<?> instrument(DynamicType.Builder<?> builder) {
    return builder
        .visit(Advice.to(SingleAdvice.class)
                   .on(named("read").or(named("write")).and(takesArgument(0, ByteBuffer.class))))
        .visit(Advice.to(RangeAdvice.class)
                   .on(named("read").or(named("write")).and(
                       takesArguments(ByteBuffer[].class, int.class, int.class))))
        .visit(Advice.to(ArrayAdvice.class)
                   .on(named("read").or(named("write")).and(takesArgument(0, ByteBuffer[].class))
                           .and(not(takesArguments(ByteBuffer[].class, int.class, int.class)))));
  }

  public static synchronized void agentmain(String configPath, Instrumentation inst)
      throws Exception {
    if (active || running)
      throw new IllegalStateException("traffic agent already active");
    if (!inst.isRetransformClassesSupported()) {
      throw new UnsupportedOperationException("JVM does not support class retransformation");
    }
    boolean nio = false;
    boolean nio2 = false;
    for (Class<?> loaded : inst.getAllLoadedClasses()) {
      if (loaded.getName().equals("org.apache.tomcat.util.net.NioEndpoint"))
        nio = true;
      if (loaded.getName().equals("org.apache.tomcat.util.net.Nio2Endpoint"))
        nio2 = true;
      if (loaded.getName().equals("org.apache.tomcat.util.net.SecureNioChannel")) {
        if (!inst.isModifiableClass(loaded)) {
          throw new UnsupportedOperationException("Tomcat TLS channel is not modifiable");
        }
        loaded.getMethod("read", ByteBuffer.class);
        loaded.getMethod("write", ByteBuffer.class);
        loaded.getMethod("getIOChannel");
        loaded.getDeclaredField("netOutBuffer");
      }
    }
    if (nio2 && !nio) {
      throw new UnsupportedOperationException("Tomcat NIO2 is not supported by this agent");
    }
    // A `java -jar` target is not known to be Tomcat until its classes are visible here.
    if (!nio) {
      throw new UnsupportedOperationException("Tomcat NIO endpoint is not loaded in this JVM");
    }
    Properties config = new Properties();
    try (Reader reader = Files.newBufferedReader(Paths.get(configPath), StandardCharsets.UTF_8)) {
      config.load(reader);
    }
    protocolV2 = "traffic-java-v2".equals(config.getProperty("protocol"));
    Set<Integer> ports = new HashSet<>();
    for (String value : config.getProperty("ports", "").split(","))
      if (!value.trim().isEmpty())
        ports.add(Integer.parseInt(value));
    selectedPorts = Collections.unmodifiableSet(ports);
    dropped.set(0);
    Socket socket = new Socket("127.0.0.1", Integer.parseInt(config.getProperty("port")));
    socket.setSoTimeout(3000);
    OutputStream output = socket.getOutputStream();
    output.write((config.getProperty("token") + "|"
        + (protocolV2 ? "traffic-java-v2" : "traffic-java-v1") + "\n")
            .getBytes(StandardCharsets.UTF_8));
    output.flush();
    if (socket.getInputStream().read() != 1) {
      socket.close();
      throw new IOException("collector authentication failed");
    }
    instrumentation = inst;
    inFlight = new AtomicInteger();
    resetQueue();
    connections.clear();
    epoch.incrementAndGet();
    running = true;
    active = true;
    try {
      transformer = new AgentBuilder.Default()
                        .disableClassFormatChanges()
                        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                        .type(named("org.apache.tomcat.util.net.SecureNioChannel"))
                        .transform((builder, type, loader, module, domain) -> instrument(builder))
                        .installOn(inst);
      Thread sender = new Thread(() -> send(socket), "traffic-plaintext-sender");
      sender.setDaemon(true);
      sender.start();
    } catch (Throwable failure) {
      active = false;
      running = false;
      socket.close();
      throw failure;
    }
  }

  /** Queues an event within the event and byte budgets. */
  static boolean enqueue(Event event) {
    long size = event.data().length;
    if (queuedBytes.addAndGet(size) > QUEUE_BYTES) {
      queuedBytes.addAndGet(-size);
      return false;
    }
    if (!queue.offer(event)) {
      queuedBytes.addAndGet(-size);
      return false;
    }
    return true;
  }

  static void resetQueue() {
    for (Event event; (event = queue.poll()) != null;)
      queuedBytes.addAndGet(-event.data().length);
    queuedBytes.set(0);
  }

  /** Reusable line encoder for the sender thread: JSON metadata plus base64 payload. */
  static final class LineWriter {
    private final StringBuilder text = new StringBuilder(256);
    private byte[] bytes = new byte[512];
    private byte[] payload = new byte[4 * ((CHUNK + 2) / 3)];
    private final Base64.Encoder base64 = Base64.getEncoder();

    void event(OutputStream out, Event event) throws IOException {
      text.setLength(0);
      text.append("{\"connection\":\"");
      escape(text, event.connection());
      text.append("\",\"local\":\"");
      escape(text, event.local());
      text.append("\",\"port\":").append(event.port()).append(",\"client\":\"");
      escape(text, event.client());
      text.append("\",\"read\":").append(event.read())
          .append(",\"incomplete\":").append(event.incomplete())
          .append(",\"payload\":\"");
      flushText(out);
      byte[] data = event.data();
      int encoded = 4 * ((data.length + 2) / 3);
      if (payload.length < encoded)
        payload = new byte[encoded];
      out.write(payload, 0, base64.encode(data, payload));
      text.append('"');
    }

    void heartbeat() {
      text.setLength(0);
      text.append("{\"type\":\"heartbeat\"");
    }

    void end(OutputStream out, long sequence) throws IOException {
      if (protocolV2)
        text.append(",\"sequence\":").append(sequence).append(",\"dropped\":").append(dropped.get());
      text.append("}\n");
      flushText(out);
    }

    // Escaping keeps the text ASCII, so each char is one byte.
    private void flushText(OutputStream out) throws IOException {
      int length = text.length();
      if (bytes.length < length)
        bytes = new byte[Math.max(length, 2 * bytes.length)];
      for (int i = 0; i < length; i++) bytes[i] = (byte) text.charAt(i);
      out.write(bytes, 0, length);
      text.setLength(0);
    }
  }

  private static final char[] HEX = "0123456789abcdef".toCharArray();

  /** Appends a JSON string body, escaping quotes, backslashes, controls and non-ASCII. */
  static void escape(StringBuilder out, String value) {
    if (value == null) {
      return;
    }
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c == '"' || c == '\\') {
        out.append('\\').append(c);
      } else if (c >= 0x20 && c < 0x7f) {
        out.append(c);
      } else {
        out.append("\\u").append(HEX[(c >> 12) & 15]).append(HEX[(c >> 8) & 15])
            .append(HEX[(c >> 4) & 15]).append(HEX[c & 15]);
      }
    }
  }

  public static void send(Socket socket) {
    try (Socket owned = socket) {
      OutputStream out = new BufferedOutputStream(socket.getOutputStream(), 1 << 16);
      InputStream in = new BufferedInputStream(socket.getInputStream(), 1 << 10);
      LineWriter line = new LineWriter();
      List<Event> batch = new ArrayList<>(BATCH);
      long sequence = 0;
      long stopDeadline = Long.MAX_VALUE;
      AtomicInteger pending = inFlight;
      while (active || !queue.isEmpty() || pending.get() > 0) {
        if (System.nanoTime() > stopDeadline)
          throw new IOException("in-flight probe calls did not drain");
        Event first = queue.poll(active ? 1000 : 100, TimeUnit.MILLISECONDS);
        batch.clear();
        if (first != null) {
          batch.add(first);
          queue.drainTo(batch, BATCH - 1);
          long size = 0;
          for (Event event : batch) size += event.data().length;
          queuedBytes.addAndGet(-size);
        } else {
          batch.add(null);
        }
        for (Event event : batch) {
          if (event == null)
            line.heartbeat();
          else
            line.event(out, event);
          line.end(out, ++sequence);
        }
        out.flush();
        for (int i = 0; i < batch.size(); i++) {
          int control = in.read();
          if (control == 2 && protocolV2) {
            active = false;
            if (stopDeadline == Long.MAX_VALUE)
              stopDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
          } else if (control != 1)
            throw new EOFException("collector disconnected");
        }
      }
      if (protocolV2) {
        out.write(("{\"type\":\"drained\",\"sequence\":" + sequence + ",\"dropped\":"
            + dropped.get() + "}\n")
                      .getBytes(StandardCharsets.UTF_8));
        out.flush();
      }

    } catch (Exception ignored) {
    } finally {
      active = false;
      try {
        if (transformer != null) {
          transformer.reset(instrumentation, AgentBuilder.RedefinitionStrategy.RETRANSFORMATION);
        }
      } finally {
        resetQueue();
        connections.clear();
        running = false;
      }
    }
  }

  private static Saved enter(Object channel, ByteBuffer buffer, int position, ByteBuffer[] buffers,
      int[] positions) {
    long generation = epoch.get();
    AtomicInteger pending = inFlight;
    pending.incrementAndGet();
    if (!active || generation != epoch.get()) {
      pending.decrementAndGet();
      return null;
    }
    Saved saved = new Saved(buffer, position, buffers, positions, channel, generation, pending);
    inside.set(true);
    return saved;
  }

  /** Entry for read/write(ByteBuffer): netOut is Tomcat's own TLS output buffer. */
  public static Saved begin(Object channel, ByteBuffer buffer, Object netOut) {
    if (!active || buffer == netOut || inside.get())
      return null;
    return enter(channel, buffer, buffer.position(), null, null);
  }

  /** Entry for read/write(ByteBuffer[], offset, length), Tomcat's gathered calls. */
  public static Saved begin(Object channel, ByteBuffer[] all, int offset, int length) {
    if (!active || inside.get())
      return null;
    ByteBuffer[] buffers = Arrays.copyOfRange(all, offset, offset + length);
    int[] positions = new int[buffers.length];
    for (int i = 0; i < buffers.length; i++) positions[i] = buffers[i].position();
    return enter(channel, null, 0, buffers, positions);
  }

  /** Entry for any other array shape, such as read/write(ByteBuffer[]). */
  public static Saved begin(Object channel, Object[] args) {
    ByteBuffer[] all = (ByteBuffer[]) args[0];
    int offset = args.length > 1 ? (Integer) args[1] : 0;
    int length = args.length > 2 ? (Integer) args[2] : all.length;
    return begin(channel, all, offset, length);
  }

  /** Resolves the connection once; a channel on another port is cached as IGNORED. */
  static ConnInfo connection(SocketChannel channel) throws IOException {
    ConnInfo info = connections.get(channel);
    if (info != null)
      return info;
    InetSocketAddress local = (InetSocketAddress) channel.getLocalAddress();
    Set<Integer> ports = selectedPorts;
    if (!ports.isEmpty() && !ports.contains(local.getPort()))
      return connections.ignore(channel);
    InetSocketAddress remote = (InetSocketAddress) channel.getRemoteAddress();
    String address = remote.getAddress().getHostAddress();
    String localText = local.toString();
    if (localText.startsWith("/"))
      localText = localText.substring(1);
    return connections.add(channel,
        (address.contains(":") ? "[" + address + "]" : address) + ":" + remote.getPort(), localText,
        local.getPort());
  }

  public static void end(Saved saved, boolean read) throws Throwable {
    if (saved == null)
      return;
    try {
      if (saved.epoch() != epoch.get() || (!active && !running))
        return;
      // Most calls on a non-blocking channel transfer nothing; skip the lookup.
      if (saved.unchanged())
        return;
      SocketChannel channel = (SocketChannel) ioChannel.get(saved.channel().getClass())
                                  .invokeExact(saved.channel());
      if (channel == null)
        return;
      ConnInfo info = connection(channel);
      if (info == ConnInfo.IGNORED)
        return;
      int[] budget = {CALL_BUDGET};
      if (saved.buffers == null) {
        capture(info, saved.buffer, saved.position, read, budget);
        return;
      }
      for (int i = 0; i < saved.buffers.length; i++)
        if (!capture(info, saved.buffers[i], saved.positions[i], read, budget))
          return;
    } finally {
      inside.set(false);
      saved.inFlight().decrementAndGet();
    }
  }

  private static void lose(ConnInfo info) {
    info.gap.set(true);
    dropped.incrementAndGet();
  }

  /** Queues the bytes between start and the buffer position; false stops the call. */
  private static boolean capture(
      ConnInfo info, ByteBuffer buffer, int start, boolean read, int[] budget) {
    int end = buffer.position();
    if (end < start) {
      lose(info);
      return true;
    }
    int offset = start;
    while (offset < end) {
      if (budget[0] <= 0) {
        lose(info);
        return false;
      }
      byte[] bytes = new byte[Math.min(Math.min(end - offset, CHUNK), budget[0])];
      if (buffer.hasArray()) {
        System.arraycopy(buffer.array(), buffer.arrayOffset() + offset, bytes, 0, bytes.length);
      } else {
        ByteBuffer view = buffer.duplicate();
        view.limit(offset + bytes.length);
        view.position(offset);
        view.get(bytes);
      }
      offset += bytes.length;
      budget[0] -= bytes.length;
      // Take the marker with the event that reports it; a failed offer restores it,
      // so a loss on this connection is never cleared without a marked event.
      boolean incomplete = info.gap.getAndSet(false);
      if (!enqueue(new Event(info.id, info.client, info.local, info.port, bytes, read, incomplete))) {
        lose(info);
        return false;
      }
    }
    return true;
  }

  public static final class SingleAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Saved enter(@Advice.This Object channel, @Advice.Argument(0) ByteBuffer buffer,
        @Advice.FieldValue("netOutBuffer") Object netOut) {
      return begin(channel, buffer, netOut);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter Saved saved, @Advice.Origin("#m") String method)
        throws Throwable {
      try {
        end(saved, method.equals("read"));
      } finally {
        if (saved != null)
          inside.set(false);
      }
    }
  }

  public static final class RangeAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Saved enter(@Advice.This Object channel, @Advice.Argument(0) ByteBuffer[] buffers,
        @Advice.Argument(1) int offset, @Advice.Argument(2) int length) {
      return begin(channel, buffers, offset, length);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter Saved saved, @Advice.Origin("#m") String method)
        throws Throwable {
      try {
        end(saved, method.equals("read"));
      } finally {
        if (saved != null)
          inside.set(false);
      }
    }
  }

  public static final class ArrayAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Saved enter(@Advice.This Object channel, @Advice.AllArguments Object[] args) {
      return begin(channel, args);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter Saved saved, @Advice.Origin("#m") String method)
        throws Throwable {
      try {
        end(saved, method.equals("read"));
      } finally {
        if (saved != null)
          inside.set(false);
      }
    }
  }
}
