import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Created by Lukas on 24-Mar-16.
 */
public class Tools {

    private static final ECNamedCurveParameterSpec ECCparam = ECNamedCurveTable.getParameterSpec("prime192v1");
    //private static final ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("prime192v1");

    public static byte[] ECPublicKey = {(byte) 0x04, (byte) 0x67, (byte) 0x88, (byte) 0x74, (byte) 0xfb, (byte) 0x3e, (byte) 0x76, (byte) 0x45, (byte) 0x26, (byte) 0x51, (byte) 0x78, (byte) 0xb7, (byte) 0x83, (byte) 0x64, (byte) 0x47, (byte) 0x75, (byte) 0xae, (byte) 0x81, (byte) 0x44, (byte) 0xa2, (byte) 0xa7, (byte) 0x20, (byte) 0xfa, (byte) 0x53, (byte) 0xd9, (byte) 0x96, (byte) 0x46, (byte) 0x48, (byte) 0xfd, (byte) 0x53, (byte) 0x91, (byte) 0x2f, (byte) 0x33, (byte) 0x3f, (byte) 0xbf, (byte) 0x90, (byte) 0xa3, (byte) 0xe7, (byte) 0xf3, (byte) 0x43, (byte) 0x09, (byte) 0x7d, (byte) 0x18, (byte) 0x55, (byte) 0x99, (byte) 0xa4, (byte) 0xc2, (byte) 0xb4, (byte) 0x07};
    public static byte[] ECPrivateKey = {(byte) 0x00, (byte) 0xa0, (byte) 0xb2, (byte) 0x95, (byte) 0xf1, (byte) 0x33, (byte) 0xdd, (byte) 0x8d, (byte) 0x7b, (byte) 0x29, (byte) 0x32, (byte) 0x25, (byte) 0x16, (byte) 0xb2, (byte) 0x43, (byte) 0xb0, (byte) 0xe8, (byte) 0x52, (byte) 0x3a, (byte) 0xbf, (byte) 0x47, (byte) 0xb5, (byte) 0xab, (byte) 0x69, (byte) 0x46};
    public static byte[] ECCertificate = {(byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0x3c, (byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x24, (byte) 0x02, (byte) 0x04, (byte) 0xf2, (byte) 0xf4, (byte) 0x9b, (byte) 0xc1, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x00, (byte) 0x30, (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x0c, (byte) 0x0a, (byte) 0x77, (byte) 0x77, (byte) 0x77, (byte) 0x2e, (byte) 0x4c, (byte) 0x43, (byte) 0x50, (byte) 0x2e, (byte) 0x62, (byte) 0x65, (byte) 0x31, (byte) 0x11, (byte) 0x30, (byte) 0x0f, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c, (byte) 0x08, (byte) 0x4b, (byte) 0x55, (byte) 0x4c, (byte) 0x65, (byte) 0x75, (byte) 0x76, (byte) 0x65, (byte) 0x6e, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x04, (byte) 0x47, (byte) 0x65, (byte) 0x6e, (byte) 0x74, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x04, (byte) 0x4f, (byte) 0x2d, (byte) 0x56, (byte) 0x6c, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x42, (byte) 0x45, (byte) 0x30, (byte) 0x1e, (byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x33, (byte) 0x32, (byte) 0x37, (byte) 0x31, (byte) 0x34, (byte) 0x31, (byte) 0x35, (byte) 0x31, (byte) 0x36, (byte) 0x5a, (byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x37, (byte) 0x30, (byte) 0x35, (byte) 0x31, (byte) 0x34, (byte) 0x31, (byte) 0x35, (byte) 0x31, (byte) 0x36, (byte) 0x5a, (byte) 0x30, (byte) 0x4d, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x0c, (byte) 0x04, (byte) 0x41, (byte) 0x6c, (byte) 0x64, (byte) 0x69, (byte) 0x31, (byte) 0x11, (byte) 0x30, (byte) 0x0f, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c, (byte) 0x08, (byte) 0x4b, (byte) 0x55, (byte) 0x4c, (byte) 0x65, (byte) 0x75, (byte) 0x76, (byte) 0x65, (byte) 0x6e, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x04, (byte) 0x47, (byte) 0x65, (byte) 0x6e, (byte) 0x74, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x04, (byte) 0x4f, (byte) 0x2d, (byte) 0x56, (byte) 0x6c, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x42, (byte) 0x45, (byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0x67, (byte) 0x88, (byte) 0x74, (byte) 0xfb, (byte) 0x3e, (byte) 0x76, (byte) 0x45, (byte) 0x26, (byte) 0x51, (byte) 0x78, (byte) 0xb7, (byte) 0x83, (byte) 0x64, (byte) 0x47, (byte) 0x75, (byte) 0xae, (byte) 0x81, (byte) 0x44, (byte) 0xa2, (byte) 0xa7, (byte) 0x20, (byte) 0xfa, (byte) 0x53, (byte) 0xd9, (byte) 0x96, (byte) 0x46, (byte) 0x48, (byte) 0xfd, (byte) 0x53, (byte) 0x91, (byte) 0x2f, (byte) 0x33, (byte) 0x3f, (byte) 0xbf, (byte) 0x90, (byte) 0xa3, (byte) 0xe7, (byte) 0xf3, (byte) 0x43, (byte) 0x09, (byte) 0x7d, (byte) 0x18, (byte) 0x55, (byte) 0x99, (byte) 0xa4, (byte) 0xc2, (byte) 0xb4, (byte) 0x07, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x82, (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0xbc, (byte) 0xe4, (byte) 0xf4, (byte) 0xe3, (byte) 0x45, (byte) 0x1d, (byte) 0xae, (byte) 0x2b, (byte) 0x8f, (byte) 0x02, (byte) 0x45, (byte) 0xb9, (byte) 0x12, (byte) 0x88, (byte) 0x68, (byte) 0x30, (byte) 0x3c, (byte) 0x2f, (byte) 0xeb, (byte) 0xc8, (byte) 0xec, (byte) 0xd2, (byte) 0x5b, (byte) 0x22, (byte) 0xc0, (byte) 0x2a, (byte) 0xcd, (byte) 0x1c, (byte) 0x47, (byte) 0xc6, (byte) 0xf6, (byte) 0x43, (byte) 0x7b, (byte) 0xa5, (byte) 0x41, (byte) 0x9c, (byte) 0xa4, (byte) 0x58, (byte) 0xcd, (byte) 0x50, (byte) 0x7f, (byte) 0x23, (byte) 0xfc, (byte) 0x24, (byte) 0xa9, (byte) 0xfb, (byte) 0xd6, (byte) 0xa6, (byte) 0xa2, (byte) 0xc2, (byte) 0x0f, (byte) 0xa7, (byte) 0x26, (byte) 0xe0, (byte) 0xc9, (byte) 0x5b, (byte) 0x2f, (byte) 0xe9, (byte) 0x55, (byte) 0x00, (byte) 0x94, (byte) 0x53, (byte) 0xaa, (byte) 0x74, (byte) 0x91, (byte) 0x9a, (byte) 0xaa, (byte) 0x63, (byte) 0xe9, (byte) 0xf3, (byte) 0x21, (byte) 0x39, (byte) 0x00, (byte) 0xd2, (byte) 0x40, (byte) 0x37, (byte) 0xd7, (byte) 0xb0, (byte) 0x51, (byte) 0xba, (byte) 0x9c, (byte) 0xd7, (byte) 0x14, (byte) 0xa1, (byte) 0xa8, (byte) 0x30, (byte) 0x49, (byte) 0x70, (byte) 0x6d, (byte) 0x5c, (byte) 0xb7, (byte) 0x98, (byte) 0xd3, (byte) 0x06, (byte) 0x60, (byte) 0xd0, (byte) 0xb1, (byte) 0xc0, (byte) 0x32, (byte) 0xba, (byte) 0xd6, (byte) 0x9b, (byte) 0x3a, (byte) 0xbb, (byte) 0x73, (byte) 0x79, (byte) 0xb2, (byte) 0x24, (byte) 0x1f, (byte) 0x86, (byte) 0x31, (byte) 0xd3, (byte) 0x6e, (byte) 0xce, (byte) 0x44, (byte) 0x7d, (byte) 0x05, (byte) 0xf6, (byte) 0x17, (byte) 0xf0, (byte) 0xf8, (byte) 0x50, (byte) 0xd1, (byte) 0x1d, (byte) 0x18, (byte) 0xa5, (byte) 0x9e, (byte) 0x34, (byte) 0x6b, (byte) 0x51, (byte) 0xd7, (byte) 0xa7, (byte) 0x24, (byte) 0xe6, (byte) 0xba, (byte) 0x24, (byte) 0xde, (byte) 0x38, (byte) 0x50, (byte) 0x5b, (byte) 0xab, (byte) 0xab, (byte) 0xcc, (byte) 0x9a, (byte) 0x13, (byte) 0x31, (byte) 0x53, (byte) 0x50, (byte) 0xec, (byte) 0x3e, (byte) 0x85, (byte) 0x99, (byte) 0xde, (byte) 0xba, (byte) 0xc2, (byte) 0x41, (byte) 0x87, (byte) 0xaf, (byte) 0x5a, (byte) 0x98, (byte) 0xe0, (byte) 0x99, (byte) 0x1d, (byte) 0x46, (byte) 0xde, (byte) 0xbd, (byte) 0xf5, (byte) 0xf4, (byte) 0x0b, (byte) 0x52, (byte) 0xb9, (byte) 0xc8, (byte) 0x7c, (byte) 0x5b, (byte) 0xf2, (byte) 0x4d, (byte) 0xf7, (byte) 0x7f, (byte) 0xaa, (byte) 0x69, (byte) 0x00, (byte) 0xb9, (byte) 0xc6, (byte) 0x2e, (byte) 0x16, (byte) 0xc9, (byte) 0x0e, (byte) 0x82, (byte) 0x38, (byte) 0x80, (byte) 0xc4, (byte) 0x1f, (byte) 0x6a, (byte) 0x28, (byte) 0x2c, (byte) 0x19, (byte) 0xe9, (byte) 0x29, (byte) 0x5b, (byte) 0xf8, (byte) 0x86, (byte) 0xee, (byte) 0x5f, (byte) 0xfe, (byte) 0x7b, (byte) 0x14, (byte) 0x8c, (byte) 0xff, (byte) 0xe1, (byte) 0x6e, (byte) 0xf0, (byte) 0x5c, (byte) 0x89, (byte) 0x31, (byte) 0xe2, (byte) 0x40, (byte) 0x40, (byte) 0x7a, (byte) 0x08, (byte) 0xb4, (byte) 0x85, (byte) 0x56, (byte) 0x6a, (byte) 0x4c, (byte) 0xc9, (byte) 0x9c, (byte) 0x0f, (byte) 0x6a, (byte) 0x69, (byte) 0x25, (byte) 0x0d, (byte) 0xbb, (byte) 0xec, (byte) 0x4f, (byte) 0x1a, (byte) 0x2e, (byte) 0xf2, (byte) 0xc7, (byte) 0x88, (byte) 0xfa, (byte) 0xa5, (byte) 0xdf, (byte) 0xfa, (byte) 0x21, (byte) 0x2b, (byte) 0xe7, (byte) 0xf0, (byte) 0x06, (byte) 0xf7, (byte) 0xb4, (byte) 0x16, (byte) 0x8a, (byte) 0x25, (byte) 0xb5, (byte) 0x4a, (byte) 0xf8};
    private static SecureRandom rand = new SecureRandom();


    public static void loadKeyInfo(String shopName) throws IOException, ClassNotFoundException {
        File file = new File("data\\" + shopName +".data");
        FileInputStream in = new FileInputStream(file);
        ObjectInputStream ois = new ObjectInputStream(in);
        ECPublicKey = (byte[])ois.readObject();
        ECPrivateKey = (byte[])ois.readObject();
        ECCertificate = (byte[])ois.readObject();
        System.out.println(ECPublicKey.length +" "+ECPrivateKey.length+" "+ECCertificate.length);
        ois.close();
    }

    public static org.bouncycastle.jce.interfaces.ECPublicKey getECPublicKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        return (org.bouncycastle.jce.interfaces.ECPublicKey) KeyFactory.getInstance("ECDH", "BC").generatePublic(new X509EncodedKeySpec(ECPublicKey));
    }


    public static org.bouncycastle.jce.interfaces.ECPrivateKey getECPrivateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {

        BigInteger D = new BigInteger(ECPrivateKey);

        KeySpec keyspec = new ECPrivateKeySpec(D,ECCparam);

        PrivateKey privkey = null;

        try{
            privkey = KeyFactory.getInstance("ECDH", "BC").generatePrivate(keyspec);
            org.bouncycastle.jce.interfaces.ECPrivateKey ecPk = (org.bouncycastle.jce.interfaces.ECPrivateKey)privkey;

            return ecPk;

        }catch( Throwable e ){

            e.printStackTrace();
        }
        return null;
    }


    public static PublicKey getPublicKey() {
        try {
            // Open keystore and retrieve private key
            KeyStore keyStore = KeyStore.getInstance("JKS");
            String fileNameStore1 = new File("certificates\\LCP.jks").getAbsolutePath();
            char[] password = "LCP".toCharArray();
            FileInputStream fis = new FileInputStream(fileNameStore1);
            keyStore.load(fis, password);
            fis.close();
            Certificate certCA = keyStore.getCertificate("LoyaltyCardProvider");
            PublicKey publicKeyCA = certCA.getPublicKey();
            return publicKeyCA;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey getPrivateKey() {
        try {
            // Open keystore and retrieve private key
            KeyStore keyStore = KeyStore.getInstance("JKS");
            String fileNameStore1 = new File("certificates\\LCP.jks").getAbsolutePath();
            char[] password = "LCP".toCharArray();
            FileInputStream fis = new FileInputStream(fileNameStore1);
            keyStore.load(fis, password);
            fis.close();
            PrivateKey privateKeyCA = (PrivateKey) keyStore.getKey("LoyaltyCardProvider", "LCP".toCharArray());
            return privateKeyCA;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static X509Certificate signCertificate(X509v1CertificateBuilder v1CertGen, PrivateKey privateKey) {
        try {
            ContentSigner signer = (ContentSigner) new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(v1CertGen.build(signer));
        } catch (OperatorCreationException | CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] encryptMessage(byte[] msg, SecretKey sessionKey) {
        try {
            Cipher c = Cipher.getInstance(Crypto.SYMMETRIC_ALGORITHM);
            //content
            byte[] encryptedContent = Crypto.encrypt(msg, sessionKey, c);
            return encryptedContent;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;

    }

    public static String decryptMessage(byte[] msg, SecretKey secretKey) {
        try {
            Cipher c = Cipher.getInstance(Crypto.SYMMETRIC_ALGORITHM);
            //content
            byte[] decryptedContent = Crypto.decrypt(msg, secretKey, c);
            return new String(decryptedContent, "UTF-8");

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decrypt(byte[] msg, SecretKey secretKey) {
        try {
            Cipher c = Cipher.getInstance(Crypto.SYMMETRIC_ALGORITHM);
            //content
            byte[] decryptedContent = Crypto.decrypt(msg, secretKey, c);
            return decryptedContent;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void printByteArray(byte[] bytes) {
        for (byte b: bytes) {
            System.out.print("0x" + String.format("%02x", b) + " ");
        }
        System.out.println();
    }

    public static byte[] applyPadding(byte[] bytes) {
        int length = bytes.length;
        int newLength = length + 16 - (length%16);
        byte[] padded = new byte[newLength];
        for (int i = 0; i < newLength; i++) {
            if (i < length) padded[i] = bytes[i];
            else padded[i] = new Byte("0");
        }
        return padded;
    }

    /**
     *
     * @return 26 bytes random pseudo ID
     */
    public static String generateRandomPseudoniem() {
        String s = new BigInteger(130, rand).toString(32);
        while (s.length() < 26) {
            s = "0"+s;
        }
        return s;
    }

    public static byte[] concatAllBytes(byte[] first, byte[]... rest) {
        int totalLength = first.length;
        for (byte[] array : rest) {
            totalLength += array.length;
        }
        byte[] result = Arrays.copyOf(first, totalLength);
        int offset = first.length;
        for (byte[] array : rest) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }
    public static byte[] increaseSize(byte[] input, int size) {
        if (input.length >= size) return input;

        byte[] output = new byte[size];
        for (int i = 0; i < input.length; i++) {
            output[i] = input[i];
        }
        for (int i = input.length; i < size; i++) {
            output[i] = new Byte("0");
        }
        return output;
    }

}
