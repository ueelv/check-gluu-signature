package lv.uee.gluu.utils;

import lv.uee.gluu.dto.AuthenticateResponseApp;
import lv.uee.gluu.dto.AuthenticateResponseServer;
import lv.uee.gluu.dto.EnrollmentResponse;
import lv.uee.gluu.exception.CheckSignatureException;

public interface RawMessageCodec {

    byte[] encodeRegisterResponse(EnrollmentResponse enrollmentResponse)
            throws CheckSignatureException;

    byte[] encodeAuthenticateResponse(AuthenticateResponseApp authenticateResponseApp)
            throws CheckSignatureException;

    byte[] encodeRegistrationSignedBytes(byte[] applicationSha256,
                                         byte[] challengeSha256, byte[] keyHandle, byte[] userPublicKey);

    byte[] encodeAuthenticateSignedBytes(byte[] applicationSha256, byte userPresence,
                                         int counter, byte[] challengeSha256);

}