package traffic.agent;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketOption;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class AgentTest {
  public static final class Channel {
    public final ByteBuffer netOutBuffer = ByteBuffer.allocate(8);
    private final SocketChannel socket;
    final AtomicInteger lookups = new AtomicInteger();

    public Channel(SocketChannel socket) {
      this.socket = socket;
    }

    public SocketChannel getIOChannel() {
      lookups.incrementAndGet();
      return socket;
    }
  }

  /** A connected-looking channel that counts address lookups. */
  static final class FakeSocket extends SocketChannel {
    final InetSocketAddress local;
    final InetSocketAddress remote;
    final AtomicInteger localLookups = new AtomicInteger();

    FakeSocket(int localPort, int remotePort) {
      super(SelectorProvider.provider());
      local = new InetSocketAddress("127.0.0.1", localPort);
      remote = new InetSocketAddress("127.0.0.1", remotePort);
    }

    @Override
    public SocketAddress getLocalAddress() {
      localLookups.incrementAndGet();
      return local;
    }

    @Override
    public SocketAddress getRemoteAddress() {
      return remote;
    }

    @Override
    public SocketChannel bind(SocketAddress a) {
      return this;
    }

    @Override
    public <T> SocketChannel setOption(SocketOption<T> o, T v) {
      return this;
    }

    @Override
    public <T> T getOption(SocketOption<T> o) {
      return null;
    }

    @Override
    public Set<SocketOption<?>> supportedOptions() {
      return Collections.emptySet();
    }

    @Override
    public SocketChannel shutdownInput() {
      return this;
    }

    @Override
    public SocketChannel shutdownOutput() {
      return this;
    }

    @Override
    public java.net.Socket socket() {
      return null;
    }

    @Override
    public boolean isConnected() {
      return true;
    }

    @Override
    public boolean isConnectionPending() {
      return false;
    }

    @Override
    public boolean connect(SocketAddress r) {
      return true;
    }

    @Override
    public boolean finishConnect() {
      return true;
    }

    @Override
    public int read(ByteBuffer d) {
      return 0;
    }

    @Override
    public long read(ByteBuffer[] d, int o, int l) {
      return 0;
    }

    @Override
    public int write(ByteBuffer s) {
      return 0;
    }

    @Override
    public long write(ByteBuffer[] s, int o, int l) {
      return 0;
    }

    @Override
    protected void implCloseSelectableChannel() {}

    @Override
    protected void implConfigureBlocking(boolean b) {}
  }

  /** Stand-in for SecureNioChannel, instrumented with the production advice. */
  public static class FakeSecureChannel {
    private ByteBuffer netOutBuffer = ByteBuffer.allocate(16);
    private final SocketChannel socket;

    public FakeSecureChannel(SocketChannel socket) {
      this.socket = socket;
    }

    public SocketChannel getIOChannel() {
      return socket;
    }

    public ByteBuffer netOut() {
      return netOutBuffer;
    }

    public int read(ByteBuffer dst) {
      dst.put(new byte[] {'i', 'n'});
      return 2;
    }

    public int write(ByteBuffer src) {
      int n = src.remaining();
      src.position(src.limit());
      return n;
    }

    public long write(ByteBuffer[] srcs, int offset, int length) {
      long n = 0;
      for (int i = offset; i < offset + length; i++) n += write(srcs[i]);
      return n;
    }

    public long read(ByteBuffer[] dsts) {
      return read(dsts[0]);
    }
  }

  private static void setPorts(Integer... ports) throws Exception {
    java.lang.reflect.Field field = Agent.class.getDeclaredField("selectedPorts");
    field.setAccessible(true);
    field.set(null, Collections.unmodifiableSet(new HashSet<>(java.util.Arrays.asList(ports))));
  }

  @Before
  public void reset() throws Exception {
    Agent.resetQueue();
    Agent.connections.clear();
    Agent.inside.remove();
    Agent.dropped.set(0);
    setPorts();
  }

  @After
  public void cleanup() throws Exception {
    Agent.active = false;
    reset();
  }

  /** Dequeues as the sender does, releasing the event's bytes from the budget. */
  private static Agent.Event take() {
    Agent.Event event = Agent.queue.remove();
    Agent.queuedBytes.addAndGet(-event.data().length);
    return event;
  }

  private static Agent.Event write(Object channel, byte... data) throws Throwable {
    ByteBuffer buffer = ByteBuffer.wrap(data);
    Agent.Saved saved = Agent.begin(channel, buffer, null);
    buffer.position(buffer.limit());
    Agent.end(saved, false);
    return Agent.queue.poll();
  }

  @Test
  public void copiesProducedAndConsumedBytesWithoutChangingBuffers() throws Throwable {
    try (ServerSocketChannel listener = ServerSocketChannel.open()) {
      listener.bind(new InetSocketAddress("127.0.0.1", 0));
      try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
          SocketChannel socket = listener.accept()) {
        Channel channel = new Channel(socket);
        Agent.active = true;
        ByteBuffer direct = ByteBuffer.allocateDirect(16);
        Agent.Saved read = Agent.begin(channel, direct, channel.netOutBuffer);
        direct.put(new byte[] {1, 2, 3});
        Agent.end(read, true);
        assertEquals(3, direct.position());
        Agent.Event first = take();
        assertArrayEquals(new byte[] {1, 2, 3}, first.data());
        assertTrue(first.read());
        assertEquals(socket.getLocalAddress().toString().substring(1), first.local());
        ByteBuffer output = ByteBuffer.wrap(new byte[] {4, 5, 6});
        Agent.Saved write = Agent.begin(channel, output, channel.netOutBuffer);
        output.position(2);
        Agent.end(write, false);
        assertEquals(2, output.position());
        Agent.Event event = take();
        assertArrayEquals(new byte[] {4, 5}, event.data());
        assertFalse(event.read());
        assertEquals(first.connection(), event.connection());
        assertNull(Agent.begin(channel, channel.netOutBuffer, channel.netOutBuffer));
        ByteBuffer one = ByteBuffer.allocate(4), two = ByteBuffer.allocate(4);
        Agent.Saved multiple = Agent.begin(channel, new ByteBuffer[] {one, two}, 0, 2);
        one.put((byte) 7);
        two.put((byte) 8);
        Agent.end(multiple, true);
        assertArrayEquals(new byte[] {7}, take().data());
        assertArrayEquals(new byte[] {8}, take().data());
        Agent.Saved legacy = Agent.begin(channel, new Object[] {new ByteBuffer[] {one}});
        one.put((byte) 9);
        Agent.end(legacy, true);
        assertArrayEquals(new byte[] {9}, take().data());
        assertFalse(Agent.inside.get());
        assertEquals(0, Agent.queuedBytes.get());
      }
    }
  }

  @Test
  public void zeroByteCallsSkipChannelLookup() throws Throwable {
    FakeSocket socket = new FakeSocket(443, 50000);
    Channel channel = new Channel(socket);
    Agent.active = true;
    ByteBuffer buffer = ByteBuffer.allocate(8);
    for (int i = 0; i < 3; i++) {
      Agent.end(Agent.begin(channel, buffer, channel.netOutBuffer), true);
      Agent.end(Agent.begin(channel, new ByteBuffer[] {buffer}, 0, 1), false);
    }
    assertEquals(0, channel.lookups.get());
    assertEquals(0, socket.localLookups.get());
    assertTrue(Agent.queue.isEmpty());
    assertEquals(0, Agent.connections.size());
    assertFalse(Agent.inside.get());
  }

  @Test
  public void unselectedPortIsResolvedOnce() throws Throwable {
    setPorts(443);
    FakeSocket ignored = new FakeSocket(8080, 50000);
    FakeSocket selected = new FakeSocket(443, 50001);
    Agent.active = true;
    for (int i = 0; i < 5; i++) assertNull(write(new Channel(ignored), (byte) i));
    assertEquals(1, ignored.localLookups.get());
    assertSame(Agent.ConnInfo.IGNORED, Agent.connections.get(ignored));
    for (int i = 0; i < 5; i++) assertNotNull(write(new Channel(selected), (byte) i));
    assertEquals(1, selected.localLookups.get());
    assertEquals("127.0.0.1:50001", Agent.connections.get(selected).client);
  }

  @Test
  public void lossMarksOnlyTheAffectedConnection() throws Throwable {
    FakeSocket a = new FakeSocket(443, 50000), b = new FakeSocket(443, 50001);
    Channel channelA = new Channel(a), channelB = new Channel(b);
    Agent.active = true;
    assertFalse(write(channelA, (byte) 1).incomplete());
    assertFalse(write(channelB, (byte) 1).incomplete());
    for (int i = 0; i < Agent.QUEUE_EVENTS; i++)
      assertTrue(Agent.enqueue(new Agent.Event("x", "c", "l", 443, new byte[1], true, false)));
    ByteBuffer lost = ByteBuffer.wrap(new byte[] {2});
    Agent.Saved saved = Agent.begin(channelA, lost, null);
    lost.position(1);
    Agent.end(saved, false);
    assertEquals(1, Agent.dropped.get());
    assertTrue(Agent.connections.get(a).gap.get());
    assertFalse(Agent.connections.get(b).gap.get());
    Agent.resetQueue();
    assertFalse("connection B inherited A's loss", write(channelB, (byte) 3).incomplete());
    assertTrue("connection A lost its loss marker", write(channelA, (byte) 3).incomplete());
    assertFalse(write(channelA, (byte) 4).incomplete());
  }

  @Test
  public void queueIsBoundedByBytes() {
    byte[] chunk = new byte[Agent.CHUNK];
    long fits = Agent.QUEUE_BYTES / chunk.length;
    for (long i = 0; i < fits; i++)
      assertTrue(Agent.enqueue(new Agent.Event("1", "c", "l", 443, chunk, true, false)));
    assertFalse(Agent.enqueue(new Agent.Event("1", "c", "l", 443, new byte[1], true, false)));
    assertEquals(fits, Agent.queue.size());
    assertEquals(Agent.QUEUE_BYTES, Agent.queuedBytes.get());
    assertTrue("burst capacity", Agent.QUEUE_EVENTS >= 4096);
    Agent.resetQueue();
    assertEquals(0, Agent.queuedBytes.get());
    assertTrue(Agent.enqueue(new Agent.Event("1", "c", "l", 443, new byte[1], true, false)));
  }

  @Test
  public void escapesJsonStrings() {
    StringBuilder out = new StringBuilder();
    Agent.escape(out, "a\"b\\c\n\u0001é[fe80::1%eth0]:443");
    assertEquals("a\\\"b\\\\c\\u000a\\u0001\\u00e9[fe80::1%eth0]:443", out.toString());
  }

  @Test
  public void instrumentedChannelCapturesThroughAdvice() throws Throwable {
    FakeSocket socket = new FakeSocket(443, 50000);
    Class<?> type = Agent.instrument(new ByteBuddy().redefine(FakeSecureChannel.class))
                        .make()
                        .load(new ClassLoader(getClass().getClassLoader()) {},
                            ClassLoadingStrategy.Default.CHILD_FIRST)
                        .getLoaded();
    Object channel = type.getConstructor(SocketChannel.class).newInstance(socket);
    Agent.active = true;
    type.getMethod("read", ByteBuffer.class).invoke(channel, ByteBuffer.allocate(4));
    Agent.Event read = Agent.queue.remove();
    assertTrue(read.read());
    assertArrayEquals(new byte[] {'i', 'n'}, read.data());
    type.getMethod("write", ByteBuffer[].class, int.class, int.class)
        .invoke(channel, new ByteBuffer[] {ByteBuffer.wrap(new byte[] {'o'})}, 0, 1);
    Agent.Event gathered = Agent.queue.remove();
    assertFalse(gathered.read());
    assertArrayEquals(new byte[] {'o'}, gathered.data());
    // The nested write(ByteBuffer) inside the gathered call was not captured twice.
    assertTrue(Agent.queue.isEmpty());
    type.getMethod("read", ByteBuffer[].class).invoke(channel, (Object) new ByteBuffer[] {ByteBuffer.allocate(4)});
    assertArrayEquals(new byte[] {'i', 'n'}, Agent.queue.remove().data());
    ByteBuffer netOut = (ByteBuffer) type.getMethod("netOut").invoke(channel);
    netOut.put(new byte[] {1, 2}).flip();
    type.getMethod("write", ByteBuffer.class).invoke(channel, netOut);
    assertTrue("Tomcat's own TLS buffer was captured", Agent.queue.isEmpty());
    assertFalse(Agent.inside.get());
  }

  @Test
  public void drainsAllQueuedEventsAfterStopControl() throws Exception {
    java.lang.reflect.Field protocol = Agent.class.getDeclaredField("protocolV2");
    protocol.setAccessible(true);
    boolean before = protocol.getBoolean(null);
    try (ServerSocketChannel listener = ServerSocketChannel.open()) {
      listener.bind(new InetSocketAddress("127.0.0.1", 0));
      try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
          SocketChannel receiver = listener.accept()) {
        receiver.socket().setSoTimeout(5000);
        Agent.active = true;
        protocol.setBoolean(null, true);
        for (int i = 0; i < 100; i++)
          assertTrue(Agent.enqueue(new Agent.Event(Integer.toString(i), "127.0.0.1:1234",
              i == 0 ? "quote\"local" : "127.0.0.1:443", 443, new byte[] {1, 2, 3}, true, false)));
        Thread sender = new Thread(() -> Agent.send(client.socket()));
        sender.start();
        java.io.BufferedReader input = new java.io.BufferedReader(new java.io.InputStreamReader(
            receiver.socket().getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
        int events = 0;
        long sequence = 0;
        for (;;) {
          String line = input.readLine();
          assertNotNull("missing drain confirmation", line);
          if (line.contains("\"type\":\"drained\"")) {
            assertTrue(line, line.contains("\"sequence\":" + sequence + ","));
            break;
          }
          assertTrue(line.contains("\"sequence\":" + (++sequence) + ","));
          if (line.contains("\"connection\":")) {
            if (events == 0)
              assertEquals("{\"connection\":\"0\",\"local\":\"quote\\\"local\",\"port\":443,"
                      + "\"client\":\"127.0.0.1:1234\",\"read\":true,\"incomplete\":false,"
                      + "\"payload\":\"AQID\",\"sequence\":1,\"dropped\":0}",
                  line);
            events++;
          }
          receiver.socket().getOutputStream().write(2);
          receiver.socket().getOutputStream().flush();
        }
        sender.join(5000);
        assertFalse("sender remained active after drain", sender.isAlive());
        assertEquals(100, events);
        assertTrue(Agent.queue.isEmpty());
        assertEquals(0, Agent.queuedBytes.get());
        assertFalse(Agent.active);
      }
    } finally {
      protocol.setBoolean(null, before);
    }
  }

  @Test
  public void waitsForInFlightCallBeforeConfirmingDrain() throws Throwable {
    java.lang.reflect.Field protocol = Agent.class.getDeclaredField("protocolV2");
    protocol.setAccessible(true);
    java.lang.reflect.Field running = Agent.class.getDeclaredField("running");
    running.setAccessible(true);
    boolean before = protocol.getBoolean(null);
    try (ServerSocketChannel listener = ServerSocketChannel.open()) {
      listener.bind(new InetSocketAddress("127.0.0.1", 0));
      try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
          SocketChannel receiver = listener.accept()) {
        receiver.socket().setSoTimeout(5000);
        Agent.active = true;
        protocol.setBoolean(null, true);
        running.setBoolean(null, true);
        ByteBuffer buffer = ByteBuffer.allocate(4);
        Agent.Saved pending = Agent.begin(new Channel(receiver), buffer, null);
        assertNotNull(pending);
        Thread sender = new Thread(() -> Agent.send(client.socket()));
        sender.start();
        java.io.BufferedReader input = new java.io.BufferedReader(new java.io.InputStreamReader(
            receiver.socket().getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
        String heartbeat = input.readLine();
        assertTrue(heartbeat.contains("heartbeat"));
        receiver.socket().getOutputStream().write(2);
        receiver.socket().getOutputStream().flush();
        buffer.put((byte) 9);
        Agent.end(pending, true);
        String data = input.readLine();
        assertTrue("in-flight event was lost", data.contains("\"connection\":"));
        receiver.socket().getOutputStream().write(2);
        receiver.socket().getOutputStream().flush();
        String drained = input.readLine();
        assertTrue(drained.contains("drained"));
        sender.join(5000);
        assertFalse(sender.isAlive());
        assertEquals(0, pending.inFlight().get());
      }
    } finally {
      protocol.setBoolean(null, before);
      running.setBoolean(null, false);
    }
  }
}
