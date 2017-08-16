package be.crydust.fernet;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.stream.Stream;

import org.junit.Test;

public class FernetTest {
    private final String secret = "JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=";
    private final String bad_secret = "badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=";

    @Test
    public void can_verify_tokens_it_generates() throws Exception {
        Stream.of("harold@heroku.com", "12345", "weird!@#$%^&*()chars", "more weird chars §§§§").forEach(plain -> {
            String token = new Fernet(secret).encrypt(plain.getBytes(UTF_8));
            String message = new String(new Fernet(secret).decrypt(token), UTF_8);
            assertThat(message, is(plain));
        });
    }

    @Test(expected = Exception.class)
    public void fails_with_a_bad_secret() throws Exception {
        String token = new Fernet(secret).encrypt("harold@heroku.com".getBytes(UTF_8));
        new Fernet(bad_secret).decrypt(token);
    }

    @Test(expected = Exception.class)
    public void fails_if_the_token_is_too_old() {
        final String token = new Fernet(secret).encrypt("harold@heroku.com".getBytes(UTF_8), ZonedDateTime.now().minus(61, ChronoUnit.SECONDS));
        new Fernet(secret).decrypt(token, Duration.ofSeconds(60L));
    }
}
