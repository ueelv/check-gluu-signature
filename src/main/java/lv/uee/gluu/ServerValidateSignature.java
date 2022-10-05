package lv.uee.gluu;

import lv.uee.gluu.dto.AuthenticateResponseServer;
import lv.uee.gluu.dto.ByteDataInputStream;
import lv.uee.gluu.dto.RawAuthenticateResponse;
import lv.uee.gluu.exception.CheckSignatureException;
import lv.uee.gluu.utils.Base64Util;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SignatureException;

import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;
import lv.uee.gluu.utils.CheckSignature;
import lv.uee.gluu.utils.KeyPairGenerator;
import lv.uee.gluu.utils.ServerUtil;

import static lv.uee.gluu.Constant.APP_ID;

public class ServerValidateSignature {
    public static void main(String[] args) throws SignatureException, CheckSignatureException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String publicKey = "BBLiQMZGA1KTP0BraawVkswxzIKtxOcB172Eg8OcgwUCyb7sqSx5kdczyI1OP9BPN82ZUV8blKilBBuKyToQCW4";
        String authenticateResponse = "{\"signatureData\":\"AQAAAAEwRAIgRiArzKDKePqN-frYYkRJV_-rpHLllv18MHkM1I3vFcQCIDQ4Bks9gHiThKW4JU-OjxLUsH-THwAZ0aXvBaLWI2V0\",\"clientData\":\"eyJvcmlnaW4iOiIiLCJjaGFsbGVuZ2UiOiJmSmVfTDA1RnhONERXVEVINVV3UzV5akhEWmU4Vjd1cWg1Ulk5SVFGRHpnIiwidHlwIjoibmF2aWdhdG9yLmlkLmdldEFzc2VydGlvbiJ9\",\"keyHandle\":\"y_KZmTf9VRwfhvXq3BHa_ytFc6ThnRzIh4f9Z5xADuarV73eZJ-1qQLX-FGKbS581FASjlp-tAtnaBLmiYbWXw\"}";

        AuthenticateResponseServer authenticateResponseObject = ServerUtil.jsonMapperWithWrapRoot()
                .readValue(authenticateResponse, AuthenticateResponseServer.class);


        ByteDataInputStream byteDataInputStream = new ByteDataInputStream(
                Base64Util.base64urldecode(authenticateResponseObject.getSignatureData()));
        RawAuthenticateResponse rawAuthenticateResponse = new RawAuthenticateResponse(
                byteDataInputStream.readSigned(), byteDataInputStream.readInt(), byteDataInputStream.readAll());

        byte[] signedBytes = packBytesToSign(hash(APP_ID), rawAuthenticateResponse.getUserPresence(),
                rawAuthenticateResponse.getCounter(), hash(authenticateResponseObject.getClientData().getRawClientData()));

        CheckSignature checkSignature = new CheckSignature(
                KeyPairGenerator.decodePublicKey(Base64Util.base64urldecode(publicKey)),
                signedBytes,
                rawAuthenticateResponse.getSignature()
        );
        System.out.println("result:" + checkSignature.check());

    }

    private static byte[] packBytesToSign(byte[] appIdHash, byte userPresence, long counter, byte[] challengeHash) {
        ByteArrayDataOutput encoded = ByteStreams.newDataOutput();
        encoded.write(appIdHash);
        encoded.write(userPresence);
        encoded.writeInt((int) counter);
        encoded.write(challengeHash);
        return encoded.toByteArray();
    }

    private static byte[] hash(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] hash(String str) {
        return hash(str.getBytes());
    }
}
