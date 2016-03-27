import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;

/**
 * Created by Lukas on 17-Mar-16.
 */
public class CreateStaticKeyPairs {

    private static ECPrivateKey ecPrivateKey;
    private static ECPublicKey ecPublicKey;
    private static byte[] sharedKey;
    private static KeyStore keyStore = null;

    public static void main(String[] args) {
        System.out.print("Shop name? ");
        String shopName = new Scanner(System.in).nextLine();
        KeyObject keyObject = createStaticKeyPairs(shopName);
        try {
            File file = new File("data\\" + shopName +".data");
            file.createNewFile();
            FileOutputStream out = new FileOutputStream(file);
            ObjectOutputStream oos = new ObjectOutputStream(out);
            //System.out.println("private key size: "+keyObject.privateKey.getD().toByteArray().length);
            byte[] publicKey = keyObject.publicKey.getQ().getEncoded();
            byte[] privateKey = keyObject.privateKey.getD().toByteArray();
            byte[] certificate = keyObject.certificate.getEncoded();

            oos.writeObject(publicKey);
            oos.writeObject(privateKey);
            oos.writeObject(certificate);

            out.close();
        } catch(Exception e) {
            e.printStackTrace();
        }

    }

    public static KeyObject createStaticKeyPairs(String shopName) {
        System.out.println("Generating keypair for shop \""+shopName+"\".");


        KeyObject keyObject = new KeyObject();
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyPair kp = generateECCKeyPair();
            ecPrivateKey = (ECPrivateKey)kp.getPrivate();
            ecPublicKey = (ECPublicKey)kp.getPublic();
            printSecret(ecPrivateKey);
            printPublic(ecPublicKey);
            keyObject.publicKey = ecPublicKey;
            keyObject.privateKey = ecPrivateKey;

            keyObject.certificate = generateCertificateForShop(ecPublicKey, shopName);
            return keyObject;
        }
        catch (NoSuchProviderException e) {
            System.out.println("Error: No such provider");
        }
        return null;
    }



    private static X509Certificate generateCertificateForShop(ECPublicKey ecPublicKey, String shopName) {
        try {
            // Open keystore and retrieve private key
            keyStore = KeyStore.getInstance("JKS");
            String fileNameStore1 = new File("certificates\\LCP.jks").getAbsolutePath();
            char[] password = "LCP".toCharArray();
            FileInputStream fis = new FileInputStream(fileNameStore1);
            keyStore.load(fis, password);
            fis.close();
            PrivateKey privateKeyCA = (PrivateKey) keyStore.getKey("LoyaltyCardProvider", "LCP".toCharArray());
            Certificate certCA =  keyStore.getCertificate("LoyaltyCardProvider");
            PublicKey publicKeyCA = certCA.getPublicKey();
            System.out.print("Public key CA (length: "+publicKeyCA.getEncoded().length+" byte): ");
            for (byte b: publicKeyCA.getEncoded()) {
                System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
            }

            // Genereer certificaat voor javacard
            BigInteger serial = BigInteger.valueOf(new Random().nextInt());
            long notUntil = System.currentTimeMillis()+1000L*60*60*24*100;
            X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(new X500Name("CN=www.LCP.be, O=KULeuven, L=Gent, ST=O-Vl, C=BE"),
                    serial , new Date(System.currentTimeMillis()), new Date(notUntil), new X500Name("CN="+shopName+", O=KULeuven, L=Gent, ST=O-Vl, C=BE"), ecPublicKey);
            //X509CertificateHolder holder = v1CertGen.build(signer);
            X509Certificate cert = signCertificate(v1CertGen, privateKeyCA);
            if (cert != null) {
                cert.checkValidity(new Date());
            }
            cert.verify(publicKeyCA);

            byte[] certificateBytes = cert.getEncoded();
            System.out.print("\nCertificate (length: "+certificateBytes.length+" byte): ");
            for (byte b: certificateBytes) {
                System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
            }
            System.out.println();

            return cert;


        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableKeyException | SignatureException | NoSuchProviderException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static X509Certificate signCertificate(X509v1CertificateBuilder v1CertGen, PrivateKey privateKey) {
        try {
            ContentSigner signer = (ContentSigner) new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(v1CertGen.build(signer));
        } catch (OperatorCreationException | CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static KeyPair generateECCKeyPair() throws NoSuchProviderException{
        try{
            ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("prime192v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecParamSpec);
            return kpg.generateKeyPair();
        } catch(NoSuchAlgorithmException | InvalidAlgorithmParameterException e){
            throw new IllegalStateException(e.getLocalizedMessage());
        }
    }

    public static void printSecret(ECPrivateKey key){
        byte[] privateKey = key.getD().toByteArray();
        System.out.println("S (Private Key) (length: "+ privateKey.length+" byte): "+ new BigInteger(1, key.getD().toByteArray()).toString(16));
        for (byte b: privateKey) {
            System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
        }
        System.out.println();
    }

    public static void printPublic(ECPublicKey key){
        byte[] publicKey = key.getQ().getEncoded();
        System.out.println("W (Public Key) (length: "+ publicKey.length+" byte): "+ new BigInteger(1, key.getQ().getEncoded()).toString(16));
        for (byte b: publicKey) {
            System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
        }
        System.out.println();
    }

    public static class KeyObject {
        public ECPublicKey publicKey = null;
        public ECPrivateKey privateKey = null;
        public X509Certificate certificate = null;
    }



}
