// Deliberately vulnerable local demo. Never deploy this code.
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class VulnerableApi {
  static String param(String query, String key) {
    if (query == null) return "";
    for (String item : query.split("&")) {
      String[] pair = item.split("=", 2);
      if (pair.length == 2 && pair[0].equals(key)) return URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
    }
    return "";
  }
  static void run(HttpExchange exchange) throws IOException {
    String command = param(exchange.getRequestURI().getQuery(), "cmd");
    try {
      // Intentional command injection for scanner demonstration.
      Process process = Runtime.getRuntime().exec(command);
      String body = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, body.getBytes(StandardCharsets.UTF_8).length);
      exchange.getResponseBody().write(body.getBytes(StandardCharsets.UTF_8));
    } catch (Exception error) {
      byte[] body = error.toString().getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(400, body.length); exchange.getResponseBody().write(body);
    } finally { exchange.close(); }
  }
  public static void main(String[] args) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 9103), 0);
    server.createContext("/run", VulnerableApi::run); server.start();
  }
}
