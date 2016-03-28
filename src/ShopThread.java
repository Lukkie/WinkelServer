import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;


public class ShopThread extends Thread {
    private Socket socket = null;
    private ObjectInputStream in = null;
    private ObjectOutputStream out = null;
    private byte[] sessionKey;
    private SecretKey secretKey = null;
    private String shopName;

    private final boolean debug = false;

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
                if (!processInput(request, in, out)) break;

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
                                 ObjectOutputStream out) throws IOException {
        System.out.println("Processing request: \""+request+"\"");
        switch (request) {
            case "SetupSecureConnection": {
                try {
                    setupSecureConnection(in, out);
                    changeLP(in, out);
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
                break;
            }

            //Test cases
            case "getSessionKey": {
                out.writeObject(secretKey);
                break;
            }

            default: {
                System.out.println("Request not recognized. Stopping connection ");
                return false;
            }
        }
        return true;

    }

    private void setupSecureConnection(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException {

        // genereer nieuw EC keypair
        // Niet nodig
        /*CreateStaticKeyPairs.KeyObject keyObject = CreateStaticKeyPairs.createStaticKeyPairs();
        ecPublicKey = (ECPublicKey)keyObject.publicKey;
        ecPrivateKey = (ECPrivateKey)keyObject.privateKey;
        certificate = keyObject.certificate;*/

        out.writeObject(Tools.ECCertificate);


        // Lees certificaat van andere partij in, check of juist en lees public key
        byte[] certificateOtherPartyByteArray = (byte[]) in.readObject();
        X509Certificate certificateOtherParty = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream byteInputStream = new ByteArrayInputStream(certificateOtherPartyByteArray);
            certificateOtherParty = (X509Certificate) certFactory.generateCertificate(byteInputStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();

        sessionKey = generateSessionKey(publicKeyOtherParty.getEncoded());
        /*System.out.println("Received W (Public Key other party) (length: "+
                ecPublicKeyOtherPartyBytes.length+" byte): "+
                new BigInteger(1, ecPublicKeyOtherPartyBytes).toString(16));*/


        secretKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
        System.out.print("SecretKey: ");
        Tools.printByteArray(secretKey.getEncoded());


    }

    private byte[] generateSessionKey(byte[] pubKeyOtherPartyBytes) {
        try {
            PublicKey pubKeyOtherParty = KeyFactory.getInstance("ECDH", "BC")
                    .generatePublic(new X509EncodedKeySpec(pubKeyOtherPartyBytes));
            KeyAgreement keyAgr;
            keyAgr = KeyAgreement.getInstance("ECDH", "BC");
            keyAgr.init(Tools.getECPrivateKey());


            keyAgr.doPhase(pubKeyOtherParty, true);
            MessageDigest hash = MessageDigest.getInstance("SHA-1");
            byte[] secret = keyAgr.generateSecret();
            System.out.print("Secret key (length: "+secret.length+"):\t");
            Tools.printByteArray(secret);
            System.out.println();
            byte[] sessionKey = hash.digest(secret);
            sessionKey = Arrays.copyOf(sessionKey, 16);
            System.out.print("Hashed secret key (length: "+sessionKey.length+"):\t");
            Tools.printByteArray(sessionKey);

            return sessionKey;
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    private void changeLP(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException {
        // EERST SECURE CHANNEL OPZETTEN (die setupSecureConnection())

        // Voor testen:
        if (debug) {
            in.readObject();
            out.writeObject(secretKey);
        }



        // Certificaat inlezen en checken.
        byte[] encryptedCertificate = (byte[])in.readObject();
        byte[] certificateBytes = Tools.decrypt(encryptedCertificate, secretKey);
        byte[] certificateBytes413 = Arrays.copyOfRange(certificateBytes, 0, 413);
        PseudoniemCertificate cert = null;
        try (ByteArrayInputStream bis = new ByteArrayInputStream(certificateBytes413);
            ObjectInput oi = new ObjectInputStream(bis)) {
            cert = (PseudoniemCertificate) oi.readObject();
        } catch(Exception e) {
            e.printStackTrace();
        }
        PublicKey pk = Tools.getPublicKey();
        boolean verified = false;
        try {
            verified = cert.verifySignature(pk);
            if (verified) System.out.println("Signature is verified");
            else System.out.println("Signature is NOT OK");

        } catch (Exception e) {
            e.printStackTrace();
        }

        if (verified) {

            // Amount versturen
            short amount = (short)Main.amount;
            ByteBuffer buffer = ByteBuffer.allocate(2);
            buffer.putShort(amount);
            byte[] encryptedAmount = Tools.encryptMessage(Tools.applyPadding(buffer.array()), secretKey);
            out.writeObject(encryptedAmount);

            // Verifieren of correct
            byte[] correctEncrypted = (byte[])in.readObject();
            byte[] correct = Tools.decrypt(correctEncrypted, secretKey);
            if (correct[0] == (byte)0x00) System.out.println("Transfer completed");
            else System.out.println("Transfer failed.");



        }
    }

}
