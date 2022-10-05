package lv.uee.gluu.exception;

public class CheckSignatureException extends Exception {

    public CheckSignatureException(String message) {
        super(message);
    }

    public CheckSignatureException(String message, Throwable cause) {
        super(message, cause);
    }

}