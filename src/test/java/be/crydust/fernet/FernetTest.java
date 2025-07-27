package be.crydust.fernet;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class FernetTest {

    private static final String SECRET = "JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=";
    private static final String BAD_SECRET = "badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=";

    @ParameterizedTest
    @ValueSource(strings = {"harold@heroku.com", "12345", "weird!@#$%^&*()chars", "more weird chars §§§§"})
    void can_verify_tokens_it_generates(String plain) {
        String token = new Fernet(SECRET).encrypt(plain.getBytes(UTF_8));
        String message = new String(new Fernet(SECRET).decrypt(token), UTF_8);
        assertThat(message).isEqualTo(plain);
    }

    @Test
    void fails_with_a_bad_secret() {
        String token = new Fernet(SECRET).encrypt("harold@heroku.com".getBytes(UTF_8));
        assertThatExceptionOfType(FernetException.class).isThrownBy(() -> new Fernet(BAD_SECRET).decrypt(token));
    }

    @Test
    void fails_if_the_token_is_too_old() {
        final String token = new Fernet(SECRET).encrypt("harold@heroku.com".getBytes(UTF_8), Instant.now().minusSeconds(61));
        assertThatExceptionOfType(FernetException.class).isThrownBy(() -> new Fernet(SECRET).decrypt(token, ofSeconds(60L)));
    }

    @Test
    void can_ignore_TTL_enforcement() {
        final String token = new Fernet(SECRET).encrypt("harold@heroku.com".getBytes(UTF_8));
        String message = new String(new Fernet(SECRET).decrypt(token, null, Instant.now().plusSeconds(9999)), UTF_8);
        assertThat(message).isEqualTo("harold@heroku.com");
    }

    @Test
    @Disabled("there is no global config")
    void can_ignore_TTL_enforcement_via_global_config() {
    }

    @Test
    void does_not_send_the_message_in_plain_text() {
        final String token = new Fernet(SECRET).encrypt("password1".getBytes(UTF_8));
        assertThat(new String(Base64.getUrlDecoder().decode(token), UTF_8)).doesNotContain("password1");
    }

    @Test
    @Disabled("not implemented")
    void allows_overriding_enforce_ttl_on_a_verifier() {
    }

}
