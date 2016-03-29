import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Security;
import java.util.Scanner;

/**
 * Created by Lukas on 28-Mar-16.
 */
public class InputThread extends Thread {

    private String shopName;

    public InputThread(String shopName) {
        this.shopName = shopName;
    }

    @Override
    public void run() {

        Scanner sc = new Scanner(System.in);

        boolean stop = false;
        while (!stop) {
            int amount = 0;
            boolean validNumber = false;
            while (!validNumber) {
                System.out.print("How many points should be added to the card? ");
                String input = sc.nextLine();
                if (input.equals("stop")) stop = true;
                else {
                    try {
                        amount = Integer.parseInt(input);
                        validNumber = true;
                    } catch (Exception e) {
                        System.out.println("Invalid amount. Please try again.");
                    }
                }
            }

            //Main.amount = amount;
            changeLP();
        }

    }

    private void changeLP() {
        String hostName = "localhost";
        int portNumber = 13000;

        try (
                Socket socket = new Socket(hostName, portNumber);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {
            System.out.println("Trying to write to Middleware");

            out.writeObject("changeLP");
            out.writeObject(shopName);


        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +
                    hostName);
            System.exit(1);
        }
    }
}
