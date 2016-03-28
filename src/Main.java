import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.net.ServerSocket;
import java.security.Security;
import java.util.Scanner;

public class Main {

    public static int amount = 20; // niet zo mooi, 20 voor test

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        Scanner sc = new Scanner(System.in);
        System.out.print("Enter name of shop: ");
        String shopName = sc.nextLine();
        int portNumber = 0;
        int LCPPortNumber = 0;

        File configFile = new File("data\\config.txt");
        try {
            BufferedReader br = new BufferedReader(new FileReader(configFile));
            String s = null;
            int portOfS = 0;
            while ((s = br.readLine()) != null) {
                if (s.charAt(0) == '%') continue;
                String name = s.split("=")[0];
                portOfS = Integer.parseInt(s.split("=")[1]);

                if (name.equals("LCP")) LCPPortNumber = portOfS;
                if (name.equals(shopName)) portNumber = portOfS;
            }
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (LCPPortNumber == 0) {
            System.out.println("Error: LCP Port Number undefined");
            System.exit(-1);
        }
        if (portNumber == 0) {
            System.out.println("Error: Config.txt doesn't contain shop with name "+shopName);
            System.exit(-1);
        }

        try {
            Tools.loadKeyInfo(shopName);
            System.out.print("Private key: "); Tools.printByteArray(Tools.ECPrivateKey);
            System.out.print("Public key: "); Tools.printByteArray(Tools.ECPublicKey);
            System.out.print("Certificate: "); Tools.printByteArray(Tools.ECCertificate);

        } catch (Exception e) {
            e.printStackTrace();
        }


        ShopThread ioThread = null;
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            System.out.println("Server \""+shopName+"\" listening on port "+portNumber);
            while (true) {
                ioThread = new ShopThread(serverSocket.accept(), shopName);
                ioThread.start();
            }
        } catch (IOException e) {
            System.err.println("Could not listen on port " + portNumber);
            System.exit(-1);
        }


    }
}
