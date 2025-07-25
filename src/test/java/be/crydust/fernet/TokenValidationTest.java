package be.crydust.fernet;

import org.junit.Test;

import java.util.Base64;

import static be.crydust.fernet.Helper.repeat;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.ZonedDateTime.now;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

public class TokenValidationTest {
    private final String SECRET = "odN/0Yu+Pwp3oIvvG8OiE5w4LsLrqfWYRb3knQtSyKI=";

    @Test
    public void is_invalid_with_a_bad_MAC_signature() {
        String generated = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8));
        byte[] bogus_hmac = repeat("1", 32).getBytes(US_ASCII);
        final byte[] bytes = Base64.getUrlDecoder().decode(generated);
        System.arraycopy(bogus_hmac, 0, bytes, bytes.length - bogus_hmac.length, bogus_hmac.length);
        final String token_with_bogus_hmac = Base64.getUrlEncoder().encodeToString(bytes);
        FernetException e = assertThrows(FernetException.class, () -> new Fernet(SECRET).decrypt(token_with_bogus_hmac));
        assertThat(e.getMessage(), is("incorrect mac"));
    }

    @Test
    public void is_invalid_with_a_large_clock_skew() {
        final String generated = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8), now().plusSeconds(61));
        FernetException e = assertThrows(FernetException.class, () -> new Fernet(SECRET).decrypt(generated));
        assertThat(e.getMessage(), is("far-future TS (unacceptable clock skew)"));
    }

    @Test
    public void is_invalid_with_bad_base64() {
        FernetException e = assertThrows(FernetException.class, () -> new Fernet(SECRET).decrypt("bad*"));
        assertThat(e.getMessage(), is("invalid base64"));
    }

    @Test
    public void is_invalid_with_an_unknown_token_version_00() {
        String generated = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8));
        byte bogus_version = (byte) 0x00;
        final byte[] bytes = Base64.getUrlDecoder().decode(generated);
        bytes[0] = bogus_version;
        final String token_with_bogus_version = Base64.getUrlEncoder().encodeToString(bytes);
        FernetException e = assertThrows(FernetException.class, () -> new Fernet(SECRET).decrypt(token_with_bogus_version));
        assertThat(e.getMessage(), is("Unknown version 0"));
    }

    @Test
    public void is_invalid_with_an_unknown_token_version_81() {
        String generated = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8));
        byte bogus_version = (byte) 0x81;
        final byte[] bytes = Base64.getUrlDecoder().decode(generated);
        bytes[0] = bogus_version;
        final String token_with_bogus_version = Base64.getUrlEncoder().encodeToString(bytes);
        FernetException e = assertThrows(FernetException.class, () -> new Fernet(SECRET).decrypt(token_with_bogus_version));
        assertThat(e.getMessage(), is("Unknown version 81"));
    }

    @Test
    public void is_invalid_with_bad_base64_encodings() {
        String token = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8));
        String[] invalid_strings = {
                "\n" + token,
                token + " ",
                token + "+",
                token.replaceFirst("(.)$", "1"),
                token.replaceFirst("(.)$", "+"),
                token.replaceFirst("(.)$", "\\\\")
        };
        for (String invalid_string : invalid_strings) {
            try {
                new Fernet(SECRET).decrypt(invalid_string);
                fail("no exception was thrown");
            } catch (FernetException ex) {
                assertThat(ex.getMessage(), is("invalid base64"));
            }
        }
    }
}

