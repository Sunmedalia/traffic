package traffic.agent;

import java.lang.reflect.Method;

// The attach API lives in tools.jar on JDK 8 and in the jdk.attach module on JDK 9+.
// It is loaded reflectively so one Java 8 class file works with both layouts.
public final class Attach {
  public static void main(String[] args) throws Exception {
    Class<?> type;
    try {
      type = Class.forName("com.sun.tools.attach.VirtualMachine");
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(
          "Java attach API is unavailable: use a JDK (tools.jar on JDK 8, jdk.attach on JDK 9+)",
          e);
    }
    Object vm = type.getMethod("attach", String.class).invoke(null, args[0]);
    Method detach = type.getMethod("detach");
    try {
      type.getMethod("loadAgent", String.class, String.class).invoke(vm, args[1], args[2]);
    } catch (java.lang.reflect.InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof Exception)
        throw (Exception) cause;
      throw e;
    } finally {
      detach.invoke(vm);
    }
  }
}
