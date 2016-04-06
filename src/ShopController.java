import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.AnchorPane;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

public class ShopController {

    private String shopName;

    private boolean loaded = false;
    private int lp = 0;
    private int amount = 0;

    private ValueHolder valueHolder = null;


    @FXML
    private AnchorPane root;
    @FXML
    private Button loadButton;
    @FXML
    private Button changeButton;
    @FXML
    private TextField LPField; // LP op kaart
    @FXML
    private TextField amountField; // amount dat je wilt toevoegen / verwijderen


    public ShopController() {
    }

    @FXML
    public void initialize() {
        loaded = false;
        changeButton.setDisable(true);
        loadButton.setDisable(false);
        amountField.setText("");
        LPField.setText("");
        LPField.setTooltip(new Tooltip("Current amount on card. Press \"Load\" first. (This value cannot be changed)"));
        amountField.textProperty().addListener((observableValue, s, s2) -> {
            amountChanged();
        });

        amountField.setStyle("-fx-control-inner-background: white");

        loadButton.setOnAction(event -> loadInfo());
        changeButton.setOnAction(event -> changeLP() );

    }

    public void returnToBeginState(boolean transferSucces) {
        loaded = false;
        changeButton.setDisable(true);
        loadButton.setDisable(false);
        amountField.setText("");
        LPField.setText("");
        amountField.setStyle("-fx-control-inner-background: white");

        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Transaction status");
        alert.setHeaderText(null);
        if (transferSucces) alert.setContentText("Transaction completed.");
        else alert.setContentText("Transaction failed!");

        alert.showAndWait();
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
        loadButton.setDisable(true);
        changeButton.setDisable(false);
    }

    private void changeLP() {
        boolean parsed = parseVariables();
        if (parsed) {
            changeButton.setDisable(true);
            if (valueHolder.setLPToAdd((short) amount)) {
                synchronized(valueHolder) {
                    valueHolder.notify();
                }
                //initialize();
            }
        }
    }
}
