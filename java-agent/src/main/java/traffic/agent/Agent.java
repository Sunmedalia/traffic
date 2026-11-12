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
import java.util.concurrent.atomic.AtomicLong;
import net.bytebuddy.agent.builder.*;
import net.bytebuddy.asm.Advice;

public final class Agent {
  public static volatile boolean active;
  public static final ArrayBlockingQueue<Event> queue = new ArrayBlockingQueue<>(128);
  public static final ThreadLocal<Boolean> inside = ThreadLocal.withInitial(() -> false);
  public static final Map<SocketChannel, Long> connections =
      Collections.synchronizedMap(new WeakHashMap<>());
  public static final AtomicLong serial = new AtomicLong();
  public static volatile boolean gap;
  private static ResettableClassFileTransformer transformer;
  private static Instrumentation instrumentation;

  public record Event(
      String connection,
      String client,
      String local,
      int port,
      byte[] data,
      boolean read,
      boolean incomplete) {}

  public record Saved(ByteBuffer[] buffers, int[] positions, Object channel) {}

  public static synchronized void agentmain(String configPath, Instrumentation inst)
      throws Exception {
    if (active) throw new IllegalStateException("traffic agent already active");
    if (!inst.isRetransformClassesSupported()) {
      throw new UnsupportedOperationException("JVM does not support class retransformation");
    }
    boolean nio = false;
    boolean nio2 = false;
    for (Class<?> loaded : inst.getAllLoadedClasses()) {
      if (loaded.getName().equals("org.apache.tomcat.util.net.NioEndpoint")) nio = true;
      if (loaded.getName().equals("org.apache.tomcat.util.net.Nio2Endpoint")) nio2 = true;
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
    Socket socket = new Socket("127.0.0.1", Integer.parseInt(config.getProperty("port")));
    socket.setSoTimeout(3000);
    OutputStream output = socket.getOutputStream();
    output.write(
        (config.getProperty("token") + "|traffic-java-v1\n")
            .getBytes(java.nio.charset.StandardCharsets.UTF_8));
    output.flush();
    if (socket.getInputStream().read() != 1) {
      socket.close();
      throw new IOException("collector authentication failed");
    }
    instrumentation = inst;
    active = true;
    try {
      transformer =
          new AgentBuilder.Default()
              .disableClassFormatChanges()
              .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
              .type(named("org.apache.tomcat.util.net.SecureNioChannel"))
              .transform(
                  (builder, type, loader, module, domain) ->
                      builder.visit(
                          Advice.to(IOAdvice.class)
                              .on(
                                  named("read")
                                      .or(named("write"))
                                      .and(
                                          takesArgument(0, ByteBuffer.class)
                                              .or(takesArgument(0, ByteBuffer[].class))))))
              .installOn(inst);
      Thread sender = new Thread(() -> send(socket), "traffic-plaintext-sender");
      sender.setDaemon(true);
      sender.start();
    } catch (Throwable failure) {
      active = false;
      socket.close();
      throw failure;
    }
  }

  public static void send(Socket socket) {
    try (socket) {
      OutputStream out = socket.getOutputStream();
      InputStream in = socket.getInputStream();
      while (active) {
        Event event = queue.poll(1, TimeUnit.SECONDS);
        String json = "{\"type\":\"heartbeat\"}";
        if (event != null)
          json =
              "{\"connection\":\""
                  + event.connection()
                  + "\",\"local\":\""
                  + event.local()
                  + "\",\"port\":"
                  + event.port()
                  + ",\"client\":\""
                  + event.client()
                  + "\",\"read\":"
                  + event.read()
                  + ",\"incomplete\":"
                  + event.incomplete()
                  + ",\"payload\":\""
                  + Base64.getEncoder().encodeToString(event.data())
                  + "\"}";
        out.write((json + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        out.flush();
        if (in.read() != 1) break;
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
      }
    }
  }

  public static Saved begin(Object channel, Object[] args) throws Exception {
    if (!active || inside.get()) return null;
    ByteBuffer[] buffers;
    if (args[0] instanceof ByteBuffer buffer) {
      java.lang.reflect.Field field = channel.getClass().getDeclaredField("netOutBuffer");
      field.setAccessible(true);
      if (buffer == field.get(channel)) return null;
      buffers = new ByteBuffer[] {buffer};
    } else {
      ByteBuffer[] all = (ByteBuffer[]) args[0];
      int offset = args.length > 1 ? (Integer) args[1] : 0;
      int length = args.length > 2 ? (Integer) args[2] : all.length;
      buffers = Arrays.copyOfRange(all, offset, offset + length);
    }
    int[] positions = new int[buffers.length];
    for (int i = 0; i < buffers.length; i++) positions[i] = buffers[i].position();
    Saved saved = new Saved(buffers, positions, channel);
    inside.set(true);
    return saved;
  }

  public static void end(Saved saved, boolean read) throws Exception {
    if (saved == null) return;
    try {
      SocketChannel channel =
          (SocketChannel)
              saved.channel().getClass().getMethod("getIOChannel").invoke(saved.channel());
      if (channel == null) return;
      InetSocketAddress remote = (InetSocketAddress) channel.getRemoteAddress();
      String address = remote.getAddress().getHostAddress();
      String client =
          (address.contains(":") ? "[" + address + "]" : address) + ":" + remote.getPort();
      long id = connections.computeIfAbsent(channel, key -> serial.incrementAndGet());
      int budget = 1024 * 1024;
      for (int i = 0; i < saved.buffers().length; i++) {
        ByteBuffer buffer = saved.buffers()[i].duplicate();
        int end = buffer.position();
        int start = saved.positions()[i];
        if (end < start) {
          gap = true;
          continue;
        }
        buffer.position(start);
        buffer.limit(end);
        while (buffer.hasRemaining()) {
          if (budget <= 0) {
            gap = true;
            return;
          }
          byte[] bytes = new byte[Math.min(Math.min(buffer.remaining(), 65536), budget)];
          buffer.get(bytes);
          budget -= bytes.length;
          boolean incomplete = gap;
          if (!queue.offer(
              new Event(
                  Long.toString(id),
                  client,
                  channel.getLocalAddress().toString().replaceFirst("^/", ""),
                  ((InetSocketAddress) channel.getLocalAddress()).getPort(),
                  bytes,
                  read,
                  incomplete))) {
            gap = true;
            return;
          }
          if (incomplete) gap = false;
        }
      }
    } finally {
      inside.set(false);
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
        if (saved != null) inside.set(false);
      }
    }
  }
}
