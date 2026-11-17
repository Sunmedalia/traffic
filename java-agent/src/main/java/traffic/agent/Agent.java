package traffic.agent;

import static net.bytebuddy.matcher.ElementMatchers.*;

import java.io.*;
import java.lang.instrument.Instrumentation;
import java.net.*;
import java.nio.*;
import java.nio.channels.SocketChannel;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import net.bytebuddy.agent.builder.*;
import net.bytebuddy.asm.Advice;

public final class Agent {
  public static volatile boolean active;
  private static volatile boolean running;
  private static final AtomicLong epoch = new AtomicLong();
  private static volatile AtomicInteger inFlight = new AtomicInteger();
  public static final ArrayBlockingQueue<Event> queue = new ArrayBlockingQueue<>(128);
  public static final ThreadLocal<Boolean> inside = ThreadLocal.withInitial(() -> false);
  public static final Map<SocketChannel, Long> connections =
      Collections.synchronizedMap(new WeakHashMap<>());
  public static final AtomicLong serial = new AtomicLong();
  public static volatile boolean gap;
  public static final AtomicLong dropped = new AtomicLong();
  private static volatile Set<Integer> selectedPorts = Set.of();
  private static volatile boolean protocolV2;
  private record Access(java.lang.reflect.Field netOut, java.lang.reflect.Method channel) {
  }
  private static final ClassValue<Access> access = new ClassValue<>() {
    protected Access computeValue(Class<?> type) {
      try {
        java.lang.reflect.Field field = type.getDeclaredField("netOutBuffer");
        field.setAccessible(true);
        return new Access(field, type.getMethod("getIOChannel"));
      } catch (ReflectiveOperationException e) {
        throw new IllegalStateException(e);
      }
    }
  };
  private record Endpoint(String client, String local, int port) {
  }
  private static final Map<SocketChannel, Endpoint> endpoints =
      Collections.synchronizedMap(new WeakHashMap<>());
  private static ResettableClassFileTransformer transformer;
  private static Instrumentation instrumentation;

  public record Event(String connection, String client, String local, int port, byte[] data,
      boolean read, boolean incomplete) {
  }

  public record Saved(
      ByteBuffer[] buffers, int[] positions, Object channel, long epoch, AtomicInteger inFlight) {
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
    Properties config = new Properties();
    try (Reader reader = Files.newBufferedReader(Path.of(configPath))) {
      config.load(reader);
    }
    protocolV2 = "traffic-java-v2".equals(config.getProperty("protocol"));
    Set<Integer> ports = new HashSet<>();
    for (String value : config.getProperty("ports", "").split(","))
      if (!value.isBlank())
        ports.add(Integer.parseInt(value));
    selectedPorts = Set.copyOf(ports);
    dropped.set(0);
    Socket socket = new Socket("127.0.0.1", Integer.parseInt(config.getProperty("port")));
    socket.setSoTimeout(3000);
    OutputStream output = socket.getOutputStream();
    output.write((config.getProperty("token") + "|"
        + (protocolV2 ? "traffic-java-v2" : "traffic-java-v1") + "\n")
            .getBytes(java.nio.charset.StandardCharsets.UTF_8));
    output.flush();
    if (socket.getInputStream().read() != 1) {
      socket.close();
      throw new IOException("collector authentication failed");
    }
    instrumentation = inst;
    inFlight = new AtomicInteger();
    epoch.incrementAndGet();
    running = true;
    active = true;
    try {
      transformer =
          new AgentBuilder.Default()
              .disableClassFormatChanges()
              .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
              .type(named("org.apache.tomcat.util.net.SecureNioChannel"))
              .transform((builder, type, loader, module, domain)
                             -> builder.visit(Advice.to(IOAdvice.class)
                                     .on(named("read")
                                             .or(named("write"))
                                             .and(takesArgument(0, ByteBuffer.class)
                                                     .or(takesArgument(0, ByteBuffer[].class))))))
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

  public static void send(Socket socket) {
    try (socket) {
      OutputStream out = socket.getOutputStream();
      InputStream in = socket.getInputStream();
      long sequence = 0;
      long stopDeadline = Long.MAX_VALUE;
      AtomicInteger pending = inFlight;
      while (active || !queue.isEmpty() || pending.get() > 0) {
        if (System.nanoTime() > stopDeadline)
          throw new IOException("in-flight probe calls did not drain");
        Event first = queue.poll(active ? 1000 : 100, TimeUnit.MILLISECONDS);
        List<Event> batch = new ArrayList<>(16);
        if (first != null) {
          batch.add(first);
          queue.drainTo(batch, 15);
        } else {
          batch.add(null);
        }
        for (Event event : batch) {
          String json;
          if (event == null)
            json = "{\"type\":\"heartbeat\"";
          else
            json = "{\"connection\":\"" + event.connection() + "\",\"local\":\"" + event.local()
                + "\",\"port\":" + event.port() + ",\"client\":\"" + event.client()
                + "\",\"read\":" + event.read() + ",\"incomplete\":" + event.incomplete()
                + ",\"payload\":\"" + Base64.getEncoder().encodeToString(event.data()) + "\"";
          if (protocolV2)
            json += ",\"sequence\":" + (++sequence) + ",\"dropped\":" + dropped.get();
          out.write((json + "}\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
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
        out.write(("{\"type\":\"drained\",\"sequence\":" + sequence
            + ",\"dropped\":" + dropped.get() + "}\n")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
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
        queue.clear();
        connections.clear();
        endpoints.clear();
        running = false;
      }
    }
  }

  public static Saved begin(Object channel, Object[] args) throws Exception {
    if (!active || inside.get())
      return null;
    ByteBuffer[] buffers;
    if (args[0] instanceof ByteBuffer buffer) {
      if (buffer == access.get(channel.getClass()).netOut().get(channel))
        return null;
      buffers = new ByteBuffer[] {buffer};
    } else {
      ByteBuffer[] all = (ByteBuffer[]) args[0];
      int offset = args.length > 1 ? (Integer) args[1] : 0;
      int length = args.length > 2 ? (Integer) args[2] : all.length;
      buffers = Arrays.copyOfRange(all, offset, offset + length);
    }
    int[] positions = new int[buffers.length];
    for (int i = 0; i < buffers.length; i++) positions[i] = buffers[i].position();
    long generation = epoch.get();
    AtomicInteger pending = inFlight;
    pending.incrementAndGet();
    if (!active || generation != epoch.get()) {
      pending.decrementAndGet();
      return null;
    }
    Saved saved = new Saved(buffers, positions, channel, generation, pending);
    inside.set(true);
    return saved;
  }

  public static void end(Saved saved, boolean read) throws Exception {
    if (saved == null)
      return;
    try {
      if (saved.epoch() != epoch.get() || (!active && !running))
        return;
      SocketChannel channel =
          (SocketChannel) access.get(saved.channel().getClass()).channel().invoke(saved.channel());
      if (channel == null)
        return;
      Endpoint endpoint = endpoints.get(channel);
      if (endpoint == null) {
        InetSocketAddress local = (InetSocketAddress) channel.getLocalAddress();
        if (!selectedPorts.isEmpty() && !selectedPorts.contains(local.getPort()))
          return;
        InetSocketAddress remote = (InetSocketAddress) channel.getRemoteAddress();
        String address = remote.getAddress().getHostAddress();
        endpoint = new Endpoint(
            (address.contains(":") ? "[" + address + "]" : address) + ":" + remote.getPort(),
            local.toString().replaceFirst("^/", ""), local.getPort());
        endpoints.put(channel, endpoint);
      }
      long id = connections.computeIfAbsent(channel, key -> serial.incrementAndGet());
      int budget = 1024 * 1024;
      for (int i = 0; i < saved.buffers().length; i++) {
        ByteBuffer buffer = saved.buffers()[i].duplicate();
        int end = buffer.position();
        int start = saved.positions()[i];
        if (end < start) {
          gap = true;
          dropped.incrementAndGet();
          continue;
        }
        buffer.position(start);
        buffer.limit(end);
        while (buffer.hasRemaining()) {
          if (budget <= 0) {
            gap = true;
            dropped.incrementAndGet();
            return;
          }
          byte[] bytes = new byte[Math.min(Math.min(buffer.remaining(), 65536), budget)];
          buffer.get(bytes);
          budget -= bytes.length;
          boolean incomplete = gap;
          if (!queue.offer(new Event(Long.toString(id), endpoint.client(), endpoint.local(),
                  endpoint.port(), bytes, read, incomplete))) {
            gap = true;
            dropped.incrementAndGet();
            return;
          }
          if (incomplete)
            gap = false;
        }
      }
    } finally {
      inside.set(false);
      saved.inFlight().decrementAndGet();
    }
  }

  public static final class IOAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Saved enter(@Advice.This Object channel, @Advice.AllArguments Object[] args)
        throws Exception {
      return begin(channel, args);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter Saved saved, @Advice.Origin("#m") String method)
        throws Exception {
      try {
        end(saved, method.equals("read"));
      } finally {
        if (saved != null)
          inside.set(false);
      }
    }
  }
}
