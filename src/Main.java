import java.io.IOException;
import java.net.ServerSocket;

public class Main {

    public static void main(String[] args) {

        String shopName = "Shop name (to be changed)";
        int shopID = 0;

        int portNumber = 15151;
        IOThread ioThread = null;
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            System.out.println("Server listening on port "+portNumber);
            while (true) {
                ioThread = new IOThread(serverSocket.accept(), shopName, shopID);
                ioThread.start();
            }
        } catch (IOException e) {
            System.err.println("Could not listen on port " + portNumber);
            System.exit(-1);
        }
    }
}
