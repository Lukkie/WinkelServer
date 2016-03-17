import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;


public class IOThread extends Thread {
    private Socket socket = null;
    private ObjectInputStream in = null;
    private ObjectOutputStream out = null;

    private String shopName;
    private int shopID;


    public IOThread(Socket socket, String shopName, int shopID) {
        super("IOThread");
        System.out.println("IOThread started");
        this.socket = socket;
        this.shopName = shopName;
        this.shopID = shopID;
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
