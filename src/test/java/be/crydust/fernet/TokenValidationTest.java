package be.crydust.fernet;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Base64;

import static be.crydust.fernet.Helper.repeat;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class TokenValidationTest {
    private static final String SECRET = "odN/0Yu+Pwp3oIvvG8OiE5w4LsLrqfWYRb3knQtSyKI=";

    @Test
    void is_invalid_with_a_bad_MAC_signature() {
        String generated = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8));
        byte[] bogusHmac = repeat("1", 32).getBytes(US_ASCII);
        final byte[] bytes = Base64.getUrlDecoder().decode(generated);
        System.arraycopy(bogusHmac, 0, bytes, bytes.length - bogusHmac.length, bogusHmac.length);
        final String token_with_bogus_hmac = Base64.getUrlEncoder().encodeToString(bytes);
        assertThatExceptionOfType(FernetException.class)
                .isThrownBy(() -> new Fernet(SECRET).decrypt(token_with_bogus_hmac))
                .withMessage("incorrect mac");
    }

    @Test
    void is_invalid_with_a_large_clock_skew() {
        final String generated = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8), Instant.now().plusSeconds(61));
        assertThatExceptionOfType(FernetException.class)
                .isThrownBy(() -> new Fernet(SECRET).decrypt(generated))
                .withMessage("far-future TS (unacceptable clock skew)");
    }

    @Test
    void is_invalid_with_bad_base64() {
        assertThatExceptionOfType(FernetException.class)
                .isThrownBy(() -> new Fernet(SECRET).decrypt("bad*"))
                .withMessage("invalid base64");
    }

    @Test
    void is_invalid_with_an_unknown_token_version_00() {
        String generated = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8));
        byte bogusVersion = (byte) 0x00;
        final byte[] bytes = Base64.getUrlDecoder().decode(generated);
        bytes[0] = bogusVersion;
        final String token_with_bogus_version = Base64.getUrlEncoder().encodeToString(bytes);
        assertThatExceptionOfType(FernetException.class)
                .isThrownBy(() -> new Fernet(SECRET).decrypt(token_with_bogus_version))
                .withMessage("Unknown version 0");
    }

    @Test
    void is_invalid_with_an_unknown_token_version_81() {
        String generated = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8));
        byte bogusVersion = (byte) 0x81;
        final byte[] bytes = Base64.getUrlDecoder().decode(generated);
        bytes[0] = bogusVersion;
        final String token_with_bogus_version = Base64.getUrlEncoder().encodeToString(bytes);
        assertThatExceptionOfType(FernetException.class)
                .isThrownBy(() -> new Fernet(SECRET).decrypt(token_with_bogus_version))
                .withMessage("Unknown version 81");
    }

    @Test
    void is_invalid_with_bad_base64_encodings() {
        String token = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8));
        String[] invalidStrings = {
                "\n" + token,
                token + " ",
                token + "+",
                token.replaceFirst("(.)$", "1"),
                token.replaceFirst("(.)$", "+"),
                token.replaceFirst("(.)$", "\\\\")
        };
        for (String invalidString : invalidStrings) {
            assertThatExceptionOfType(FernetException.class)
                    .isThrownBy(() -> new Fernet(SECRET).decrypt(invalidString))
                    .withMessage("invalid base64");
        }
    }
}

