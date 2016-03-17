import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;


public class ShopThread extends Thread {
    private Socket socket = null;
    private ObjectInputStream in = null;
    private ObjectOutputStream out = null;

    private String shopName;


    public ShopThread(Socket socket, String shopName) {
        super("ShopThread");
        System.out.println("ShopThread started");
        this.socket = socket;
        this.shopName = shopName;
    }


    @Override
    public void run() {

        try {
            in = new ObjectInputStream(this.socket.getInputStream());
            out = new ObjectOutputStream(this.socket.getOutputStream());
            System.out.println("Waiting for requests.");
            String request;
            while ((request = (String)in.readObject()) != null) {
                processInput(request, in, out);

            }
            System.out.println("Stopping run method");
        }
        catch (IOException e) {
            System.out.println("Connection lost, shutting down thread.");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

    }


    private boolean processInput(String request, ObjectInputStream in,
                                 ObjectOutputStream out)  {
        System.out.println("Processing request: \""+request+"\"");
        switch (request) {
            case("Test"): {
                System.out.println("Hello world");
                break;
            }

            default: {
                System.out.println("Request not recognized. Stopping connection ");
                return false;
            }
        }
        return true;

    }

}
