package be.crydust.fernet;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

/**
 * A fernet key is the base64url encoding of the following fields:
 * Signing-key, Encryption-key
 *
 * <ul>
 * <li>Signing-key, 128 bits</li>
 * <li>Encryption-key, 128 bits</li>
 * </ul>
 */
public class Key {
    private static final String SIGNING_KEY_ALGORITHM = "HmacSHA256";
    private static final String ENCRYPTION_KEY_ALGORITHM = "AES";

    private final SecretKey signingKey;
    private final SecretKey encryptionKey;
    private String base64urlEncodedSecret = null;

    public Key(String base64urlEncodedSecret) {
        this(Base64.getUrlDecoder().decode(base64urlEncodedSecret));
    }

    public Key(byte[] secretBytes) {
        this(Arrays.copyOfRange(secretBytes, 0, 16),
                Arrays.copyOfRange(secretBytes, 16, 32));
    }

    public Key(byte[] signingKeyBytes, byte[] encryptionKeyBytes) {
        this(new SecretKeySpec(signingKeyBytes, SIGNING_KEY_ALGORITHM),
                new SecretKeySpec(encryptionKeyBytes, ENCRYPTION_KEY_ALGORITHM));
    }

    public Key(SecretKey signingKey, SecretKey encryptionKey) {
        assert SIGNING_KEY_ALGORITHM.equals(signingKey.getAlgorithm());
        assert signingKey.getEncoded().length == 16;
        assert ENCRYPTION_KEY_ALGORITHM.equals(encryptionKey.getAlgorithm());
        assert encryptionKey.getEncoded().length == 16;

        this.signingKey = signingKey;
        this.encryptionKey = encryptionKey;
    }

    public SecretKey getSigningKey() {
        return signingKey;
    }

    public SecretKey getEncryptionKey() {
        return encryptionKey;
    }

    @Override
    public String toString() {
        if (base64urlEncodedSecret == null) {
            try {
                final ByteArrayOutputStream bos = new ByteArrayOutputStream();
                bos.write(signingKey.getEncoded());
                bos.write(encryptionKey.getEncoded());
                base64urlEncodedSecret = Base64.getUrlEncoder().encodeToString(bos.toByteArray());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return base64urlEncodedSecret;
    }
}
