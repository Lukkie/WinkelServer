import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateEncodingException;
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

    private ShopController shopController;

    private final boolean debug = true;

    public ShopThread(Socket socket, String shopName, ShopController shopController) {
        super("ShopThread");
        System.out.println("ShopThread started");
        this.socket = socket;
        this.shopName = shopName;
        this.shopController = shopController;
    }


    @Override
    public void run() {

        try {
            in = new ObjectInputStream(this.socket.getInputStream());
            out = new ObjectOutputStream(this.socket.getOutputStream());
            System.out.println("Waiting for requests.");
            String request;
            if ((request = (String)in.readObject()) != null) {
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
                                 ObjectOutputStream out) throws IOException {
        System.out.println("Processing request: \""+request+"\"");
        switch (request) {
            case "SetupSecureConnection": {
                try {
                    setupSecureConnection(in, out);
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
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
        X509Certificate certificateOtherParty = null;
        try {
            certificateOtherParty = loadCertificate(in, out, false);
        } catch(IOException e) {
            // TODO: Pop-up genereren zodat shop weet dat zn certificate revoked is.
            throw new IOException("Certificate is revoked");
        }
        System.out.println("Serial other party's certificate: "+certificateOtherParty.getSerialNumber());
        if (isCertificateRevoked(certificateOtherParty)) {
            System.out.println("Certificate is revoked"); // verbinding afbreken
            // TODO: Pop-up genereren zodat shop weet dat kaart z'n certificate revoked is.
        }
        else {
            System.out.println("Certificate is valid. Continuing..");


            PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();

            sessionKey = generateSessionKey(publicKeyOtherParty.getEncoded());
            /*System.out.println("Received W (Public Key other party) (length: "+
                ecPublicKeyOtherPartyBytes.length+" byte): "+
                new BigInteger(1, ecPublicKeyOtherPartyBytes).toString(16));*/


            secretKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
            System.out.print("SecretKey: ");
            Tools.printByteArray(secretKey.getEncoded());


            changeLP(in, out);
        }

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
        ValueHolder valueHolder =  new ValueHolder();

        // EERST SECURE CHANNEL OPZETTEN (die setupSecureConnection())

        // Voor testen:
        if (debug) {
            in.readObject();
            out.writeObject(secretKey);
        }


        // LP Ophalen
        byte[] encryptedLP = (byte[])in.readObject();
        byte[] decryptedLP = Tools.decrypt(encryptedLP, secretKey);
        valueHolder.setLP(Tools.byteArrayToShort(Arrays.copyOfRange(decryptedLP, 0, 2)));


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
            //Open GUI-venster met prompt voor amount, check of juist, en bij cancel: zend null

            try {
                shopController.updateInfo(valueHolder);
                synchronized (valueHolder) {
                    //new ChangeLPWindow(this, );
                    try {
                        valueHolder.wait();   // gui moet valueHolder.notify() oproepen.
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                    // Amount versturen
                    short amount = (short)valueHolder.getAmount();
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
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        else out.writeObject(null);
    }

    /**
     * True als revoked
     * False als legit
     */
    private boolean isCertificateRevoked(X509Certificate certificate) {

        String hostName = "localhost";
        int portNumber = 26262;



        try (
                Socket socket = new Socket(hostName, portNumber);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {
            byte[] certificateBytes = certificate.getEncoded();

            System.out.println("Trying to write to OCSP");

            out.writeObject("isCertificateRevoked");
            out.writeObject("Shop");

            System.out.println("CertificateBytes.length = "+certificateBytes.length);
            Tools.printByteArray(certificateBytes);
            out.writeObject(certificateBytes);

            //setup secure connection
            X509Certificate certificateOtherParty = loadCertificate(in, out, false);
            out.writeObject(Tools.ECCertificate);

            PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();
            byte[] sessionKey2 = generateSessionKey(publicKeyOtherParty.getEncoded());
            SecretKey secretKey2 = new SecretKeySpec(sessionKey2, 0, sessionKey2.length, "AES");

            byte[] answerCertificate = Tools.decrypt((byte[])in.readObject(), secretKey2);
            answerCertificate = Arrays.copyOfRange(answerCertificate, 0, certificateBytes.length);
            if (!Arrays.equals(certificateBytes, answerCertificate)) {
                System.out.print("Sent certificate (length: "+certificateBytes.length+"): "); Tools.printByteArray(certificateBytes);
                System.out.print("Received certificate (length: "+answerCertificate.length+"): "); Tools.printByteArray(answerCertificate);

                System.out.println("Middleman detected, assume certificate to be revoked");
                return true;
            }

            byte[] answer = Tools.decrypt((byte[]) in.readObject(), secretKey2);
            System.out.println("Answer = "+answer[0]);
            if (answer[0] == (byte)0x00) return true; // 0x00 als het revoked is
            else return false;



        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +
                    hostName);
            System.exit(1);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        return true;
    }
    private X509Certificate loadCertificate(ObjectInputStream in, ObjectOutputStream out, boolean encrypted) throws IOException, ClassNotFoundException {
        byte[] certificateByteArray = (byte[]) in.readObject();
        if (encrypted) certificateByteArray = Arrays.copyOfRange(Tools.decrypt(certificateByteArray, secretKey),0,413);
        X509Certificate certificate = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream byteInputStream = new ByteArrayInputStream(certificateByteArray);
            certificate = (X509Certificate)certFactory.generateCertificate(byteInputStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return certificate;
    }


}
