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
}
