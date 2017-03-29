package be.crydust.fernet;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.*;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;

public class Fernet implements Serializable {

    private static final byte VERSION = (byte) 0x80;
    private static final int HMAC_LENGTH = 32;
    private static final int VERSION_LENGTH = 1;
    private static final int TIMESTAMP_LENGTH = 8;
    private static final int IV_LENGTH = 16;
    private static final int MIN_TOKEN_LENGTH = VERSION_LENGTH + TIMESTAMP_LENGTH + IV_LENGTH + HMAC_LENGTH;
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int BLOCK_SIZE = 16;
    private static final int MAX_CLOCK_SKEW = 60;

    private final Key key;

    public Fernet(String base64urlEncodedSecret) {
        this(new Key(base64urlEncodedSecret));
    }

    public Fernet(byte[] secretBytes) {
        this(new Key(secretBytes));
    }

    public Fernet(Key key) {
        this.key = key;
    }

    private static IvParameterSpec generateIV() {
        final byte[] ivBytes = new byte[IV_LENGTH];
        try {
            SecureRandom.getInstanceStrong().nextBytes(ivBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return new IvParameterSpec(ivBytes);
    }

    private static String encrypt(byte[] message, IvParameterSpec iv, ZonedDateTime now, Key key) {

        // 1. Record the current time for the timestamp field.
        final byte[] timestamp = packLongBigendian(now.toEpochSecond());

        // 2. Choose a unique IV.
        // see constructor

        // 3. Construct the ciphertext:
        // i. Pad the message to a multiple of 16 bytes (128 bits) per RFC 5652, section 6.3. This is the same padding technique used in PKCS #7 v1.5 and all versions of SSL/TLS (cf. RFC 5246, section 6.2.3.2 for TLS 1.2).
        // ii. Encrypt the padded message using AES 128 in CBC mode with the chosen IV and user-supplied encryption-key.
        final byte[] ciphertext;
        try {
            final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key.getEncryptionKey(), iv);
            ciphertext = cipher.doFinal(message);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }

        final ByteArrayOutputStream bos;
        try {
            bos = new ByteArrayOutputStream();
            bos.write(VERSION);
            bos.write(timestamp);
            bos.write(iv.getIV());
            bos.write(ciphertext);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        final byte[] hmac;
        try {
            // 4. Compute the HMAC field as described above using the user-supplied signing-key.
            final Mac sha256_HMAC = Mac.getInstance(HMAC_ALGORITHM);
            sha256_HMAC.init(key.getSigningKey());
            hmac = sha256_HMAC.doFinal(bos.toByteArray());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        try {
            // 5. Concatenate all fields together in the format above.
            bos.write(hmac);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // 6. base64url encode the entire token.
        return Base64.getUrlEncoder().encodeToString(bos.toByteArray());
    }

    private static byte[] decrypt(String base64urlEncodedToken, Duration ttl, ZonedDateTime now, Key key) {
        if (ttl != null && ttl.isNegative()) {
            throw new IllegalArgumentException("time-to-live must be positive");
        }

        // 1. base64url decode the token.
        final byte[] tokenBytes;
        try {
            tokenBytes = Base64.getUrlDecoder().decode(base64urlEncodedToken);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("invalid base64", e);
        }

        // 2. Ensure the first byte of the token is 0x80.
        final byte version = tokenBytes[0];
        if (version != VERSION) {
            throw new RuntimeException("Unknown version " + version);
        }

        if (tokenBytes.length < MIN_TOKEN_LENGTH) {
            throw new RuntimeException("too short");
        }

        if ((tokenBytes.length - MIN_TOKEN_LENGTH) % BLOCK_SIZE != 0) {
            throw new RuntimeException("payload size not multiple of block size");
        }

        // 3. If the user has specified a maximum age (or "time-to-live") for the token, ensure the recorded timestamp is not too far in the past.
        final long nowEpoch = now.toEpochSecond();
        final byte[] timestampBytes = Arrays.copyOfRange(tokenBytes, VERSION_LENGTH, VERSION_LENGTH + TIMESTAMP_LENGTH);
        final long timestamp = unpackLongBigendian(timestampBytes);
        if (ttl != null) {
            final long goodTill = timestamp + ttl.getSeconds();
            if (goodTill <= nowEpoch) {
                throw new RuntimeException("expired TTL");
            }
        }
        if (timestamp >= nowEpoch + MAX_CLOCK_SKEW) {
            throw new RuntimeException("far-future TS (unacceptable clock skew)");
        }

        try {
            final byte[] hmac = Arrays.copyOfRange(tokenBytes, tokenBytes.length - HMAC_LENGTH, tokenBytes.length);
            // 4. Recompute the HMAC from the other fields and the user-supplied signing-key.
            final Mac sha256_HMAC = Mac.getInstance(HMAC_ALGORITHM);
            sha256_HMAC.init(key.getSigningKey());
            sha256_HMAC.update(tokenBytes, 0, tokenBytes.length - HMAC_LENGTH);
            final byte[] recomputedHmac = sha256_HMAC.doFinal();
            // 5. Ensure the recomputed HMAC matches the HMAC field stored in the token, using a constant-time comparison function.
            if (!MessageDigest.isEqual(recomputedHmac, hmac)) {
                throw new RuntimeException("incorrect mac");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        final byte[] ivBytes = Arrays.copyOfRange(tokenBytes, VERSION_LENGTH + TIMESTAMP_LENGTH, VERSION_LENGTH + TIMESTAMP_LENGTH + IV_LENGTH);
        final IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // 6. Decrypt the ciphertext field using AES 128 in CBC mode with the recorded IV and user-supplied encryption-key.
        // 7. Unpad the decrypted plaintext, yielding the original message.
        byte[] message;
        try {
            final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key.getEncryptionKey(), iv);
            message = cipher.doFinal(tokenBytes, VERSION_LENGTH + TIMESTAMP_LENGTH + IV_LENGTH, tokenBytes.length - (VERSION_LENGTH + TIMESTAMP_LENGTH + IV_LENGTH) - HMAC_LENGTH);
        } catch (BadPaddingException e) {
            throw new RuntimeException("payload padding error", e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }

        return message;
    }

    public static Key generateKey() {
        return Key.generate();
    }

    static byte[] packLongBigendian(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    static long unpackLongBigendian(byte[] bytes) {
        if (bytes.length != 8) {
            throw new IllegalArgumentException("Expected an array of 8 bytes, not " + bytes.length);
        }
        return ByteBuffer.wrap(bytes).getLong();
    }

    public String encrypt(byte[] message) {
        return this.encrypt(message, generateIV(), ZonedDateTime.now());
    }

    public String encrypt(byte[] message, ZonedDateTime now) {
        return this.encrypt(message, generateIV(), now);
    }

    String encrypt(byte[] message, IvParameterSpec iv, ZonedDateTime now) {
        return encrypt(message, iv, now, this.key);
    }

    public byte[] decrypt(String token) {
        return this.decrypt(token, null, ZonedDateTime.now());
    }

    public byte[] decrypt(String token, Duration ttl) {
        return this.decrypt(token, ttl, ZonedDateTime.now());
    }

    byte[] decrypt(String token, Duration ttl, ZonedDateTime now) {
        return decrypt(token, ttl, now, this.key);
    }

    /**
     * A fernet key is the base64url encoding of the following fields:
     * Signing-key, Encryption-key
     * <ul>
     * <li>Signing-key, 128 bits</li>
     * <li>Encryption-key, 128 bits</li>
     * </ul>
     */
    public static class Key implements Serializable {
        private static final String SIGNING_KEY_ALGORITHM = "HmacSHA256";
        private static final String ENCRYPTION_KEY_ALGORITHM = "AES";

        private final SecretKey signingKey;
        private final SecretKey encryptionKey;
        private volatile String base64urlEncodedSecret = null;

        public Key(String base64urlEncodedSecret) {
            this(Base64.getUrlDecoder().decode(base64urlEncodedSecret));
            this.base64urlEncodedSecret = base64urlEncodedSecret;
        }

        public Key(byte[] secretBytes) {
            this(Arrays.copyOfRange(secretBytes, 0, 16),
                    Arrays.copyOfRange(secretBytes, 16, 32));
        }

        private Key(byte[] signingKeyBytes, byte[] encryptionKeyBytes) {
            this(new SecretKeySpec(signingKeyBytes, SIGNING_KEY_ALGORITHM),
                    new SecretKeySpec(encryptionKeyBytes, ENCRYPTION_KEY_ALGORITHM));
        }

        private Key(SecretKey signingKey, SecretKey encryptionKey) {
            assert SIGNING_KEY_ALGORITHM.equals(signingKey.getAlgorithm());
            assert signingKey.getEncoded().length == 16;
            assert ENCRYPTION_KEY_ALGORITHM.equals(encryptionKey.getAlgorithm());
            assert encryptionKey.getEncoded().length == 16;

            this.signingKey = signingKey;
            this.encryptionKey = encryptionKey;
        }

        private static Key generate() {
            final byte[] bytes = new byte[32];
            try {
                SecureRandom.getInstanceStrong().nextBytes(bytes);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
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
                        try {
                            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
                            bos.write(signingKey.getEncoded());
                            bos.write(encryptionKey.getEncoded());
                            this.base64urlEncodedSecret = localSecret = Base64.getUrlEncoder().encodeToString(bos.toByteArray());
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            }
            return localSecret;
        }
    }
}
