package traffic.agent;

import static org.junit.Assert.*;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import org.junit.Test;

public class AgentTest {
  public static final class Channel {
    public final ByteBuffer netOutBuffer = ByteBuffer.allocate(8);
    private final SocketChannel socket;

    public Channel(SocketChannel socket) {
      this.socket = socket;
    }

    public SocketChannel getIOChannel() {
      return socket;
    }
  }

  @Test
  public void copiesProducedAndConsumedBytesWithoutChangingBuffers() throws Exception {
    try (ServerSocketChannel listener = ServerSocketChannel.open()) {
      listener.bind(new InetSocketAddress("127.0.0.1", 0));
      try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
          SocketChannel socket = listener.accept()) {
        Channel channel = new Channel(socket);
        Agent.active = true;
        Agent.queue.clear();
        Agent.inside.set(false);
        try {
          ByteBuffer direct = ByteBuffer.allocateDirect(16);
          Agent.Saved read = Agent.begin(channel, new Object[] {direct});
          direct.put(new byte[] {1, 2, 3});
          Agent.end(read, true);
          assertEquals(3, direct.position());
          assertArrayEquals(new byte[] {1, 2, 3}, Agent.queue.remove().data());
          ByteBuffer output = ByteBuffer.wrap(new byte[] {4, 5, 6});
          Agent.Saved write = Agent.begin(channel, new Object[] {output});
          output.position(2);
          Agent.end(write, false);
          assertEquals(2, output.position());
          Agent.Event event = Agent.queue.remove();
          assertArrayEquals(new byte[] {4, 5}, event.data());
          assertFalse(event.read());
          assertNull(Agent.begin(channel, new Object[] {channel.netOutBuffer}));
          ByteBuffer one = ByteBuffer.allocate(4), two = ByteBuffer.allocate(4);
          Agent.Saved multiple =
              Agent.begin(channel, new Object[] {new ByteBuffer[] {one, two}, 0, 2});
          one.put((byte) 7);
          two.put((byte) 8);
          Agent.end(multiple, true);
          assertArrayEquals(new byte[] {7}, Agent.queue.remove().data());
          assertArrayEquals(new byte[] {8}, Agent.queue.remove().data());
          for (int i = 0; i < 128; i++) Agent.queue.add(event);
          output.position(0);
          Agent.Saved overflow = Agent.begin(channel, new Object[] {output});
          output.position(1);
          Agent.end(overflow, false);
          assertTrue(Agent.gap);
          assertFalse(Agent.inside.get());
        } finally {
          Agent.active = false;
          Agent.queue.clear();
          Agent.connections.clear();
          Agent.inside.remove();
          Agent.gap = false;
        }
      }
    }
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
        Agent.queue.clear();
        Agent.active = true;
        protocol.setBoolean(null, true);
        for (int i = 0; i < 40; i++)
          Agent.queue.add(new Agent.Event(Integer.toString(i), "127.0.0.1:1234", "127.0.0.1:443",
              443, new byte[] {1}, true, false));
        Thread sender = new Thread(() -> Agent.send(client.socket()));
        sender.start();
        java.io.BufferedReader input = new java.io.BufferedReader(new java.io.InputStreamReader(
            receiver.socket().getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
        int events = 0;
        for (;;) {
          String line = input.readLine();
          assertNotNull("missing drain confirmation", line);
          if (line.contains("\"type\":\"drained\""))
            break;
          assertTrue(line.contains("\"sequence\":"));
          if (line.contains("\"connection\":"))
            events++;
          receiver.socket().getOutputStream().write(2);
          receiver.socket().getOutputStream().flush();
        }
        sender.join(5000);
        assertFalse("sender remained active after drain", sender.isAlive());
        assertEquals(40, events);
        assertTrue(Agent.queue.isEmpty());
        assertFalse(Agent.active);
      }
    } finally {
      Agent.active = false;
      Agent.queue.clear();
      protocol.setBoolean(null, before);
    }
  }
  @Test
  public void waitsForInFlightCallBeforeConfirmingDrain() throws Exception {
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
        Agent.queue.clear();
        Agent.active = true;
        protocol.setBoolean(null, true);
        running.setBoolean(null, true);
        ByteBuffer buffer = ByteBuffer.allocate(4);
        Agent.Saved pending = Agent.begin(new Channel(receiver), new Object[] {buffer});
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
      Agent.active = false;
      Agent.queue.clear();
      Agent.inside.remove();
      protocol.setBoolean(null, before);
      running.setBoolean(null, false);
    }
  }
}
