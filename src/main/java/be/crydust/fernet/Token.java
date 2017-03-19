package be.crydust.fernet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;

public class Token {

    private static final byte VERSION = (byte) 0x80;
    private static final long TTL_NONE = -1L;
    private static final int HMAC_LENGTH = 32;
    private static final int VERSION_LENGTH = 1;
    private static final int TIMESTAMP_LENGTH = 8;
    private static final int IV_LENGTH = 16;
    private static final int MIN_TOKEN_LENGTH = VERSION_LENGTH + TIMESTAMP_LENGTH + IV_LENGTH + HMAC_LENGTH;
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int BLOCK_SIZE = 16;
    private static final int MAX_CLOCK_SKEW = 60;

    private final ZonedDateTime now;
    private final IvParameterSpec iv;
    private final byte[] message;
    private final Key key;
    private String base64urlEncodedToken = null;

    public Token(byte[] message, Key key) {
        this(ZonedDateTime.now(), generateIV(), message, key);
    }

    public Token(ZonedDateTime now, IvParameterSpec iv, byte[] message, Key key) {
        this(now, iv, message, key, null);
    }

    private Token(ZonedDateTime now, IvParameterSpec iv, byte[] message, Key key, String base64urlEncodedToken) {
        this.now = now;
        this.iv = iv;
        this.message = message;
        this.key = key;
        this.base64urlEncodedToken = base64urlEncodedToken;
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

    public static Token decrypt(String base64urlEncodedToken, Key key) {
        return decrypt(ZonedDateTime.now(), base64urlEncodedToken, key, TTL_NONE);
    }

    public static Token decrypt(String base64urlEncodedToken, Key key, long ttl) {
        return decrypt(ZonedDateTime.now(), base64urlEncodedToken, key, ttl);
    }

    public static Token decrypt(ZonedDateTime now, String base64urlEncodedToken, Key key, long ttl) {
        if (ttl != TTL_NONE && ttl < 1L) {
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
        final long timestamp = BitPacking.unpackLongBigendian(timestampBytes);
        if (ttl != TTL_NONE) {
            final long goodTill = timestamp + ttl;
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

        return new Token(now, iv, message, key, base64urlEncodedToken);
    }


    public byte[] getMessage() {
        return Arrays.copyOf(message, message.length);
    }

    private static String generate(ZonedDateTime now, IvParameterSpec iv, byte[] message, Key key) {

        // 1. Record the current time for the timestamp field.
        final byte[] timestamp = BitPacking.packLongBigendian(now.toEpochSecond());

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

    @Override
    public String toString() {
        if (base64urlEncodedToken == null) {
            base64urlEncodedToken = generate(now, iv, message, key);
        }
        return base64urlEncodedToken;
    }
}
