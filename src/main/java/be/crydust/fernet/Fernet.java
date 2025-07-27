package be.crydust.fernet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

public final class Fernet implements Serializable {
    private static final long serialVersionUID = -9057111545600036176L;
    private static final byte VERSION = (byte) 0x80;
    private static final int HMAC_LENGTH = 32;
    private static final int VERSION_LENGTH = 1;
    private static final int TIMESTAMP_LENGTH = 8;
    private static final int IV_LENGTH = 16;
    private static final int MIN_TOKEN_LENGTH = VERSION_LENGTH + TIMESTAMP_LENGTH + IV_LENGTH + HMAC_LENGTH;
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int BLOCK_SIZE = 16;
    private static final long MAX_CLOCK_SKEW = 60;

    private static final SecureRandom SECURE_RANDOM;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new FernetException(e);
        }
    }

    private final Key key;

    public Fernet() {
        this(Key.generate());
    }

    public Fernet(String base64urlEncodedSecret) {
        this(Key.valueOf(base64urlEncodedSecret));
    }

    public Fernet(byte[] secretBytes) {
        this(new Key(secretBytes));
    }

    private Fernet(Key key) {
        this.key = key;
    }

    private static IvParameterSpec generateIV() {
        final byte[] ivBytes = new byte[IV_LENGTH];
        SECURE_RANDOM.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    private static String encrypt(byte[] message, IvParameterSpec iv, Instant now, Key key) {

        // 1. Record the current time for the timestamp field.
        final byte[] timestamp = packLongBigEndian(now.getEpochSecond());

        // 2. Choose a unique IV.
        // see generateIV

        // 3. Construct the ciphertext:
        // i. Pad the message to a multiple of 16 bytes (128 bits) per RFC 5652, section 6.3. This is the same padding
        // technique used in PKCS #7 v1.5 and all versions of SSL/TLS (cf. RFC 5246, section 6.2.3.2 for TLS 1.2).
        // ii. Encrypt the padded message using AES 128 in CBC mode with the chosen IV and user-supplied encryption-key.
        final byte[] ciphertext;
        try {
            final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(ENCRYPT_MODE, key.getEncryptionKey(), iv);
            ciphertext = cipher.doFinal(message);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException
                 | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            throw new FernetException(e);
        }

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            bos.write(VERSION);
            bos.write(timestamp);
            bos.write(iv.getIV());
            bos.write(ciphertext);
        } catch (IOException e) {
            throw new FernetException(e);
        }

        final byte[] hmac;
        try {
            // 4. Compute the HMAC field as described above using the user-supplied signing-key.
            final Mac sha256HMAC = Mac.getInstance(HMAC_ALGORITHM);
            sha256HMAC.init(key.getSigningKey());
            hmac = sha256HMAC.doFinal(bos.toByteArray());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new FernetException(e);
        }

        try {
            // 5. Concatenate all fields together in the format above.
            bos.write(hmac);
        } catch (IOException e) {
            throw new FernetException(e);
        }

        // 6. base64url encode the entire token.
        return Base64.getUrlEncoder().encodeToString(bos.toByteArray());
    }

    private static byte[] decrypt(String base64urlEncodedToken, Duration ttl, Instant now, Key key) {
        if (ttl != null && ttl.isNegative()) {
            throw new IllegalArgumentException("time-to-live must be positive");
        }

        // 1. base64url decode the token.
        final byte[] tokenBytes;
        try {
            tokenBytes = Base64.getUrlDecoder().decode(base64urlEncodedToken);
        } catch (IllegalArgumentException e) {
            throw new FernetException("invalid base64", e);
        }

        // 2. Ensure the first byte of the token is 0x80.
        final byte version = tokenBytes[0];
        if (version != VERSION) {
            throw new FernetException("Unknown version " + Integer.toHexString(version & 0xFF));
        }

        if (tokenBytes.length < MIN_TOKEN_LENGTH) {
            throw new FernetException("too short");
        }

        if ((tokenBytes.length - MIN_TOKEN_LENGTH) % BLOCK_SIZE != 0) {
            throw new FernetException("payload size not multiple of block size");
        }

        // 3. If the user has specified a maximum age (or "time-to-live") for the token, ensure the recorded timestamp
        // is not too far in the past.
        final long nowEpoch = now.getEpochSecond();
        final long timestamp = unpackLongBigEndian(tokenBytes, VERSION_LENGTH, TIMESTAMP_LENGTH);
        if (ttl != null) {
            final long goodTill = timestamp + ttl.getSeconds();
            if (goodTill <= nowEpoch) {
                throw new FernetException("expired TTL");
            }
        }
        if (timestamp >= nowEpoch + MAX_CLOCK_SKEW) {
            throw new FernetException("far-future TS (unacceptable clock skew)");
        }

        try {
            final byte[] hmac = Arrays.copyOfRange(tokenBytes, tokenBytes.length - HMAC_LENGTH, tokenBytes.length);
            // 4. Recompute the HMAC from the other fields and the user-supplied signing-key.
            final Mac sha256HMAC = Mac.getInstance(HMAC_ALGORITHM);
            sha256HMAC.init(key.getSigningKey());
            sha256HMAC.update(tokenBytes, 0, tokenBytes.length - HMAC_LENGTH);
            final byte[] recomputedHmac = sha256HMAC.doFinal();
            // 5. Ensure the recomputed HMAC matches the HMAC field stored in the token, using a constant-time
            // comparison function.
            if (!MessageDigest.isEqual(recomputedHmac, hmac)) {
                throw new FernetException("incorrect mac");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new FernetException(e);
        }

        final IvParameterSpec iv = new IvParameterSpec(tokenBytes, VERSION_LENGTH + TIMESTAMP_LENGTH, IV_LENGTH);

        // 6. Decrypt the ciphertext field using AES 128 in CBC mode with the recorded IV and user-supplied
        // encryption-key.
        // 7. Unpad the decrypted plaintext, yielding the original message.
        final byte[] message;
        try {
            final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(DECRYPT_MODE, key.getEncryptionKey(), iv);
            final int offset = VERSION_LENGTH + TIMESTAMP_LENGTH + IV_LENGTH;
            final int length = tokenBytes.length - offset - HMAC_LENGTH;
            message = cipher.doFinal(tokenBytes, offset, length);
        } catch (BadPaddingException e) {
            throw new FernetException("payload padding error", e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                 | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
            throw new FernetException(e);
        }

        return message;
    }

    static byte[] packLongBigEndian(long value) {
        return ByteBuffer.allocate(8)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(value)
                .array();
    }

    static long unpackLongBigEndian(byte[] bytes, int offset, int length) {
        if (length != 8) {
            throw new IllegalArgumentException("Expected an array of 8 bytes, not " + length);
        }
        return ByteBuffer.wrap(bytes, offset, length)
                .order(ByteOrder.BIG_ENDIAN)
                .getLong();
    }

    public String encrypt(byte[] message) {
        return this.encrypt(message, generateIV(), Instant.now());
    }

    public String encrypt(byte[] message, Instant now) {
        return this.encrypt(message, generateIV(), now);
    }

    String encrypt(byte[] message, IvParameterSpec iv, Instant now) {
        return encrypt(message, iv, now, this.key);
    }

    public byte[] decrypt(String token) {
        return this.decrypt(token, null, Instant.now());
    }

    public byte[] decrypt(String token, Duration ttl) {
        return this.decrypt(token, ttl, Instant.now());
    }

    byte[] decrypt(String token, Duration ttl, Instant now) {
        return decrypt(token, ttl, now, this.key);
    }

    @Override
    public String toString() {
        return key.toString();
    }

    /**
     * A fernet key is the base64url encoding of the following fields:
     * Signing-key, Encryption-key
     * <ul>
     * <li>Signing-key, 128 bits</li>
     * <li>Encryption-key, 128 bits</li>
     * </ul>
     */
    private static final class Key implements Serializable {
        private static final long serialVersionUID = -5265692531084945591L;
        private static final String SIGNING_KEY_ALGORITHM = "HmacSHA256";
        private static final String ENCRYPTION_KEY_ALGORITHM = "AES";

        private final SecretKey signingKey;
        private final SecretKey encryptionKey;
        private transient volatile String base64urlEncodedSecret = null;

        private static Key valueOf(String s) {
            try {
                switch (s.length()) {
                    case 32:
                        return new Key(s.getBytes(US_ASCII));
                    case 43:
                        // falls through
                    case 44:
                        try {
                            return new Key(Base64.getUrlDecoder().decode(s));
                        } catch (IllegalArgumentException ex) {
                            return new Key(Base64.getDecoder().decode(s));
                        }
                    default:
                        throw new FernetException("invalid secret");
                }
            } catch (ArrayIndexOutOfBoundsException | IllegalArgumentException ex) {
                throw new FernetException("invalid secret", ex);
            }
        }

        private Key(byte[] secretBytes) {
            if (secretBytes.length != 32) {
                throw new IllegalArgumentException("Expected an array of 32 bytes, not " + secretBytes.length);
            }
            this.signingKey = new SecretKeySpec(secretBytes, 0, 16, SIGNING_KEY_ALGORITHM);
            this.encryptionKey = new SecretKeySpec(secretBytes, 16, 16, ENCRYPTION_KEY_ALGORITHM);
        }

        private static Key generate() {
            final byte[] bytes = new byte[32];
            SECURE_RANDOM.nextBytes(bytes);
            return new Key(bytes);
        }

        private SecretKey getSigningKey() {
            return signingKey;
        }

        private SecretKey getEncryptionKey() {
            return encryptionKey;
        }

        @Override
        public String toString() {
            String localSecret = this.base64urlEncodedSecret;
            if (localSecret == null) {
                synchronized (this) {
                    localSecret = this.base64urlEncodedSecret;
                    if (localSecret == null) {
                        localSecret = Base64.getUrlEncoder().encodeToString(toBytes());
                        this.base64urlEncodedSecret = localSecret;
                    }
                }
            }
            return localSecret;
        }

        private byte[] toBytes() {
            final byte[] signingKeyBytes = signingKey.getEncoded();
            final byte[] encryptionKeyBytes = encryptionKey.getEncoded();
            final byte[] secretBytes = new byte[32];
            System.arraycopy(signingKeyBytes, 0, secretBytes, 0, 16);
            System.arraycopy(encryptionKeyBytes, 0, secretBytes, 16, 16);
            return secretBytes;
        }
    }
}
