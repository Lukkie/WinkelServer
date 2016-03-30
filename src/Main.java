import javafx.scene.control.TextInputDialog;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.Security;
import java.util.Optional;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application{

    //public static short amount = 20; // niet zo mooi, 20 voor test
    //public static short LP = 40; // 40 voor test

    @Override
    public void start(Stage primaryStage) throws Exception{
        String shopName = getShopName();
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



        FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("Shop.fxml"));
        Parent root = loader.load();
        ShopController shopController = loader.getController();
        shopController.setShopName(shopName);
        primaryStage.setTitle(shopName);
        Scene rootScene = new Scene(root);
        primaryStage.setScene(rootScene);
        primaryStage.show();



        new RequestAccepter(shopName, portNumber, shopController).start();
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());



        launch(args);


    }

    private String getShopName() {
        TextInputDialog dialog = new TextInputDialog("Aldi");
        dialog.setTitle("Shop chooser");
        dialog.setHeaderText("What is the name of the shop?");
        dialog.setContentText("Shop name:");

        // Traditional way to get the response value.
        Optional<String> result = dialog.showAndWait();
        if (result.isPresent()){
            return result.get();
        }
        return null;
    }
}
