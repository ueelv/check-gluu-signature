package lv.uee.gluu.dto;

import lv.uee.gluu.exception.BadInputException;

public class RawAuthenticateResponse {
    public static final byte USER_PRESENT_FLAG = 0x01;

    private final byte userPresence;
    private final long counter;
    private final byte[] signature;

    public RawAuthenticateResponse(byte userPresence, long counter, byte[] signature) {
        this.userPresence = userPresence;
        this.counter = counter;
        this.signature = signature;
    }

    /**
     * Bit 0 is set to 1, which means that user presence was verified. (This
     * version of the protocol doesn't specify a way to request authentication
     * responses without requiring user presence.) A different value of bit 0,
     * as well as bits 1 through 7, are reserved for future use. The values of
     * bit 1 through 7 SHOULD be 0
     */
    public byte getUserPresence() {
        return userPresence;
    }

    /**
     * This is the big-endian representation of a counter value that the U2F
     * device increments every time it performs an authentication operation.
     */
    public long getCounter() {
        return counter;
    }

    /**
     * This is a ECDSA signature (on P-256)
     */
    public byte[] getSignature() {
        return signature;
    }

    public void checkUserPresence() throws BadInputException {
        if (userPresence != USER_PRESENT_FLAG) {
            throw new BadInputException("User presence invalid during authentication");
        }
    }
}
