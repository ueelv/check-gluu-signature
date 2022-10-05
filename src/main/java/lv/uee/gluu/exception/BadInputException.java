package lv.uee.gluu.exception;

public class BadInputException extends RuntimeException {

    private static final long serialVersionUID = -2738024707341148557L;

    public BadInputException(String message) {
        super(message);
    }

    public BadInputException(String message, Throwable cause) {
        super(message, cause);
    }
}
