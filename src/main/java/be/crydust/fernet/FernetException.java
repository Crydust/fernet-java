package be.crydust.fernet;

public class FernetException extends RuntimeException {
    public FernetException() {
    }

    public FernetException(String message) {
        super(message);
    }

    public FernetException(String message, Throwable cause) {
        super(message, cause);
    }

    public FernetException(Throwable cause) {
        super(cause);
    }
}
