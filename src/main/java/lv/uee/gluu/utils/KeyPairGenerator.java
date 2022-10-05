package lv.uee.gluu.utils;

import lv.uee.gluu.exception.CheckSignatureException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.security.*;

public  class KeyPairGenerator {

    private static BouncyCastleProvider bouncyCastleProvider;

    public static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    static {
        bouncyCastleProvider = BOUNCY_CASTLE_PROVIDER;
    }

    public KeyPair generateKeyPair() throws CheckSignatureException {
        SecureRandom random = new SecureRandom();

        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        try {
            java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("ECDSA", bouncyCastleProvider);
            g.initialize(ecSpec, random);
            KeyPair keyPair = g.generateKeyPair();

            return keyPair;
        } catch (NoSuchAlgorithmException ex) {
            throw new CheckSignatureException("Failed to generate key pair", ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new CheckSignatureException("Failed to generate key pair", ex);
        }
    }

    public byte[] encodePublicKey(PublicKey publicKey) {
        byte[] encodedWithPadding = publicKey.getEncoded();
        byte[] encoded = new byte[65];
        System.arraycopy(encodedWithPadding, 26, encoded, 0, encoded.length);

        //System.out.println(" Encoded public key: " + Utils.encodeHexString(encoded));

        return encoded;
    }

    public static PublicKey decodePublicKey(byte[] encodedPublicKey) throws SignatureException {
        X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
        ECPoint point = curve.getCurve().decodePoint(encodedPublicKey);

        try {
            return KeyFactory.getInstance("ECDSA").generatePublic(
                    new ECPublicKeySpec(point,
                            new ECParameterSpec(
                                    curve.getCurve(),
                                    curve.getG(),
                                    curve.getN(),
                                    curve.getH()
                            )
                    )
            );
        } catch (GeneralSecurityException ex) {
            throw new SignatureException(ex);
        }
    }

    public byte[] sign(byte[] signedData, PrivateKey privateKey) throws CheckSignatureException {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA", bouncyCastleProvider);
            signature.initSign(privateKey);
            signature.update(signedData);
            return signature.sign();
        } catch (NoSuchAlgorithmException ex) {
            throw new CheckSignatureException("Error when signing", ex);
        } catch (SignatureException ex) {
            throw new CheckSignatureException("Error when signing", ex);
        } catch (InvalidKeyException ex) {
            throw new CheckSignatureException("Error when signing", ex);
        }
    }

}
