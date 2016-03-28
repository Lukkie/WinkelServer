import org.bouncycastle.operator.OperatorCreationException;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;

/**
 * Created by Lukas on 27-Mar-16.
 */
public class PseudoniemCertificate implements Serializable {
    private byte[] pseudoniem; // length 26
    private long validUntil; // lengte = long size (64 bit = 8 byte)
    private byte[] signature;

    public PseudoniemCertificate(byte[] pseudoniem, long validUntil) {
        this.pseudoniem = pseudoniem;
        this.validUntil = validUntil;
    }

    /**
     * In volgorde:
     * 16 byte subject
     * 16 byte issuer
     * 8 byte validUntil
     * 4 byte int met [lengte] van payload
     * [lengte] byte payload
     *
     * @return
     */
    private byte[] toByteArray() {

        byte[] validUntilBytes = ByteBuffer.allocate(Long.BYTES).putLong(validUntil).array();
        return Tools.concatAllBytes(pseudoniem, validUntilBytes);
    }

    public byte[] getBytes() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(this);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ex) {
                // ignore close exception
            }
            try {
                bos.close();
            } catch (IOException ex) {
                // ignore close exception
            }
        }
        return null;
    }



    public void setValidUntil(long validUntil) {
        this.validUntil = validUntil;
    }


    public long getValidUntil() {
        return validUntil;
    }


    public boolean isValid() {
        return (validUntil > System.currentTimeMillis());
    }

    public void sign(PrivateKey privateKey) throws OperatorCreationException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Signature sig = Signature.getInstance("SHA1WithRSA", "BC");
        sig.initSign(privateKey);
        byte[] data = this.toByteArray();
        sig.update(data);
        signature = sig.sign();
        System.out.println("Signature length: "+signature.length);
    }

    public boolean verifySignature(PublicKey publicKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA1WithRSA", "BC");
        sig.initVerify(publicKey);
        sig.update(this.toByteArray());
        return sig.verify(signature);
    }


}
