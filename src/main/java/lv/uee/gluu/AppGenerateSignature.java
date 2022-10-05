package lv.uee.gluu;

import lv.uee.gluu.dto.AuthenticateRequest;
import lv.uee.gluu.dto.AuthenticateResponseApp;
import lv.uee.gluu.exception.CheckSignatureException;
import lv.uee.gluu.utils.*;
import org.apache.commons.codec.digest.DigestUtils;
import org.json.JSONObject;

import java.nio.charset.Charset;
import java.security.KeyPair;

import static lv.uee.gluu.Constant.*;

public class AppGenerateSignature {

    public static void main(String[] args) throws CheckSignatureException {
        RawMessageCodec rawMessageCodec = new RawMessageCodecImpl();
        KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
        keyPairGenerator.generateKeyPair();
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        byte[] publicKey = keyPairGenerator.encodePublicKey(keyPair.getPublic());
        System.out.println("publicKey:" + Base64Util.base64urlencode(publicKey));


        JSONObject clientData = new JSONObject();
        clientData.put(JSON_PROPERTY_REQUEST_TYPE, REQUEST_TYPE_AUTHENTICATE);
        clientData.put(JSON_PROPERTY_SERVER_CHALLENGE, CHALLENGE);
        clientData.put(JSON_PROPERTY_SERVER_ORIGIN, ORIGIN);

        String clientDataString = clientData.toString();
        AuthenticateResponseApp authenticateResponse =
                authenticate(new AuthenticateRequest(VERSION, AuthenticateRequest.USER_PRESENCE_SIGN, CHALLENGE,
                        APP_ID, Base64Util.base64urldecode(KEY_HANDLE)), clientDataString, keyPair);

        byte[] resp = rawMessageCodec.encodeAuthenticateResponse(authenticateResponse);

        JSONObject response = new JSONObject();
        response.put("signatureData", Base64Util.base64urlencode(resp));
        response.put("clientData", Base64Util.base64urlencode(clientDataString.getBytes(Charset.forName("ASCII"))));
        response.put("keyHandle", KEY_HANDLE);

        System.out.println("authenticateResponse:" + response);

    }

    public static AuthenticateResponseApp authenticate(AuthenticateRequest authenticateRequest,
                                                       String clientDataRaw, KeyPair keyPair)
            throws CheckSignatureException {
        UserPresenceVerifier userPresenceVerifier = new UserPresenceVerifierImpl();
        RawMessageCodec rawMessageCodec = new RawMessageCodecImpl();
        KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
        String application = authenticateRequest.getApplication();

        int counter = 1;
        byte userPresence = userPresenceVerifier.verifyUserPresence();
        byte[] applicationSha256 = DigestUtils.sha256(application);
        byte[] clientData256 = DigestUtils.sha256(clientDataRaw);
        byte[] signedData = rawMessageCodec.encodeAuthenticateSignedBytes(applicationSha256,
                userPresence, counter, clientData256);

        byte[] signature = keyPairGenerator.sign(signedData, keyPair.getPrivate());
        return new AuthenticateResponseApp(userPresence, counter, signature);
    }
}
