import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;


public class TestClient {

	public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
		String hostName = "localhost";
		int portNumber = 14004;

        System.out.println(Tools.ECCertificate.length);

		try (
            Socket socket = new Socket(hostName, portNumber);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {
            System.out.println("Trying to write to server");
            out.writeObject("SetupSecureConnection");
            System.out.println("Wrote to server");



            byte[] input = (byte[])in.readObject();
            System.out.println("Received bytes for certificate");
            for (byte b: input) {
                System.out.print("0x" + String.format("%02x", b) + " ");
            }

            //throw new InterruptedException("test");

            out.writeObject(input); // Dummy: Zend zelfde public key terug
            Thread.sleep(500L);

            out.writeObject("getSessionKey");
            SecretKey secretKey = (SecretKey)in.readObject();


            short amount = (short) 20;
            ByteBuffer buffer = ByteBuffer.allocate(2);
            buffer.putShort(amount);
            byte[] amountBytes = new byte[2];
            out.writeObject(Tools.encryptMessage(Tools.applyPadding(buffer.array()), secretKey));


            // Test certificaat genereren
            // psuedoniem genereren
            String pseudoString = Tools.generateRandomPseudoniem();
            System.out.println("Generated pseudo: "+pseudoString+" (length: "+pseudoString.length()+")");
            System.out.println("Pseudo byte array length: "+pseudoString.getBytes().length);

            // certificaat genereren
            PseudoniemCertificate pseudoCertificate = null;
            try {
                pseudoCertificate = generatePseudoCertificate(pseudoString);
            } catch (Exception e) {
                e.printStackTrace();
            }

            byte[] encryptedCertificate = Tools.encryptMessage(Tools.applyPadding(pseudoCertificate.getBytes()), secretKey);
            out.writeObject(encryptedCertificate);
            System.out.println("Certificate size: "+pseudoCertificate.getBytes().length);
            System.out.println("Encrypted certificate size: "+encryptedCertificate.length);

            byte[] shortArrayEncrypted = (byte[])in.readObject();
            byte[] shortArray = Tools.decrypt(shortArrayEncrypted, secretKey);
            System.out.println("shortArray[0] = "+shortArray[0]);
            System.out.println("shortArray[1] = "+shortArray[1]);

            byte[] confirmatie = new byte[1];
            confirmatie[0] = (byte)0x00;
            out.writeObject(Tools.encryptMessage(Tools.applyPadding(confirmatie), secretKey));


            System.out.println("\nEnding client");
	        } catch (UnknownHostException e) {
	            System.err.println("Don't know about host " + hostName);
	            System.exit(1);
	        } catch (IOException e) {
	            System.err.println("Couldn't get I/O for the connection to " +
	                hostName);
	            System.exit(1);
	        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }


    }

    private static PseudoniemCertificate generatePseudoCertificate(String pseudoString) throws
            KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {
        System.out.println("PseudoString size: "+pseudoString.length());

        // Open keystore and retrieve private key
        KeyStore keyStore = KeyStore.getInstance("JKS");
        String fileNameStore1 = new File("certificates\\LCP.jks").getAbsolutePath();
        char[] password = "LCP".toCharArray();
        FileInputStream fis = new FileInputStream(fileNameStore1);
        keyStore.load(fis, password);
        fis.close();
        PrivateKey privateKeyCA = (PrivateKey) keyStore.getKey("LoyaltyCardProvider", "LCP".toCharArray());
        java.security.cert.Certificate certCA =  keyStore.getCertificate("LoyaltyCardProvider");
        PublicKey publicKeyCA = certCA.getPublicKey();

        // Generate certificate
        PseudoniemCertificate cert = new PseudoniemCertificate(pseudoString.getBytes(), System.currentTimeMillis() + 1000L*60*60*24*100);
        try {
            cert.sign(privateKeyCA);
            if (cert.verifySignature(publicKeyCA)) System.out.println("Signature verified");
            else System.out.println("Signature invalid");
        }
        catch(Exception e) {
            e.printStackTrace();
        }
        return cert;



    }

}
