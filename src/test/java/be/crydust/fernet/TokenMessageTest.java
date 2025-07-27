package be.crydust.fernet;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class TokenMessageTest {
    private static final String SECRET = "odN/0Yu+Pwp3oIvvG8OiE5w4LsLrqfWYRb3knQtSyKI=";

    @Test
    void refuses_to_decrypt_if_invalid() {
        final String generated = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8), Instant.now().plusSeconds(61));
        assertThatExceptionOfType(FernetException.class)
                .isThrownBy(() -> new Fernet(SECRET).decrypt(generated))
                .withMessage("far-future TS (unacceptable clock skew)");
    }

    @Test
    void gives_back_the_original_message_in_plain_text() {
        final String token = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8));
        assertThat(new String(new Fernet(SECRET).decrypt(token), UTF_8)).isEqualTo("hello");
    }

    @Test
    void correctly_handles_an_empty_message() {
        final String token = new Fernet(SECRET).encrypt("".getBytes(UTF_8));
        assertThat(new String(new Fernet(SECRET).decrypt(token), UTF_8)).isEqualTo("");
    }
}
