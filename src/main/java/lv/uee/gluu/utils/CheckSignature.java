package lv.uee.gluu.utils;

import java.security.*;

public class CheckSignature {
    private final PublicKey publicKey;
    private final byte[] signedBytes;
    private final byte[] signature;

    public CheckSignature(PublicKey publicKey, byte[] signedBytes, byte[] signature) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.publicKey = publicKey;
        this.signedBytes = signedBytes;
        this.signature = signature;
    }


    public boolean check() throws SignatureException {
        boolean isValid = false;
        try {
            Signature ecdsaSignature = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSignature.initVerify(publicKey);
            ecdsaSignature.update(signedBytes);

            isValid = ecdsaSignature.verify(signature);
        } catch (GeneralSecurityException ex) {
            throw new SignatureException(ex);
        }
        return isValid;
    }
}
