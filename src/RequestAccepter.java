import java.io.IOException;
import java.net.ServerSocket;

/**
 * Created by Lukas on 29-Mar-16.
 */
public class RequestAccepter extends Thread {

    private String shopName;
    private int portNumber;
    private ShopController shopController;

    public RequestAccepter(String shopName, int portNumber, ShopController shopController) {
        this.shopName = shopName;
        this.portNumber = portNumber;
        this.shopController = shopController;
    }


    @Override
    public void run() {
        ShopThread ioThread = null;
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            System.out.println("Server \""+shopName+"\" listening on port "+portNumber);
            while (true) {
                ioThread = new ShopThread(serverSocket.accept(), shopName, shopController);
                ioThread.start();
            }
        } catch (IOException e) {
            System.err.println("Could not listen on port " + portNumber);
            System.exit(-1);
        }
    }

}
