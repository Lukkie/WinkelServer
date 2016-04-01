import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.Event;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.AnchorPane;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ResourceBundle;

public class ShopController {

    private String shopName;

    private boolean loaded = false;
    private int lp = 0;
    private int amount = 0;

    private ValueHolder valueHolder = null;


    @FXML
    private AnchorPane root;
    @FXML
    private Button button;
    @FXML
    private TextField LPField; // LP op kaart
    @FXML
    private TextField amountField; // amount dat je wilt toevoegen / verwijderen


    public ShopController() {
    }

    @FXML
    public void initialize() {
        loaded = false;
        button.setText("Load");
        amountField.setText("");
        LPField.setText("");
        LPField.setTooltip(new Tooltip("Current amount on card. Press \"Load\" first. (This value cannot be changed)"));
        amountField.textProperty().addListener((observableValue, s, s2) -> {
            amountChanged();
        });

        amountField.setStyle("-fx-control-inner-background: white");

        button.setOnAction(event -> loadInfo());

    }


    public void amountChanged() {
        if (loaded) {
            boolean parsed = parseVariables();
            if (parsed) {
                if (lp + amount < 0) amountField.setStyle("-fx-control-inner-background: red");
                else {
                    amountField.setStyle("-fx-control-inner-background: green");
                }
            }
            else {
                amountField.setStyle("-fx-control-inner-background: grey");
            }
        }
    }

    private void loadInfo() {
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

    public void setShopName(String shopName) {
        this.shopName = shopName;
    }

    private boolean parseVariables() {
        try {
            lp = Integer.parseInt(LPField.getText());
            amount = Integer.parseInt(amountField.getText());
            return true;
        }catch(Exception e) {

        }
        return false;
    }

    public void updateInfo(ValueHolder valueHolder) {
        this.valueHolder = valueHolder;
        LPField.setText(""+valueHolder.getLP());
        loaded = true;
        button.setText("Change LP");
        button.setOnAction(event -> changeLP() );
    }

    private void changeLP() {
        boolean parsed = parseVariables();
        if (parsed) {
            if (valueHolder.setLPToAdd((short) lp)) {
                synchronized(valueHolder) {
                    valueHolder.notify();
                }
                initialize();
            }
        }
    }
}
