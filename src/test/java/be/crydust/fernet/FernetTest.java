package be.crydust.fernet;

import org.junit.Ignore;
import org.junit.Test;

import java.time.Instant;
import java.util.Base64;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.Duration.ofSeconds;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

public class FernetTest {

    private final String secret = "JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=";
    private final String bad_secret = "badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=";

    @Test
    public void can_verify_tokens_it_generates() {
        Stream.of("harold@heroku.com", "12345", "weird!@#$%^&*()chars", "more weird chars §§§§").forEach(plain -> {
            String token = new Fernet(secret).encrypt(plain.getBytes(UTF_8));
            String message = new String(new Fernet(secret).decrypt(token), UTF_8);
            assertThat(message, is(plain));
        });
    }

    @Test(expected = FernetException.class)
    public void fails_with_a_bad_secret() {
        String token = new Fernet(secret).encrypt("harold@heroku.com".getBytes(UTF_8));
        new Fernet(bad_secret).decrypt(token);
    }

    @Test(expected = FernetException.class)
    public void fails_if_the_token_is_too_old() {
        final String token = new Fernet(secret).encrypt("harold@heroku.com".getBytes(UTF_8), Instant.now().minusSeconds(61));
        new Fernet(secret).decrypt(token, ofSeconds(60L));
    }

    @Test
    public void can_ignore_TTL_enforcement() {
        final String token = new Fernet(secret).encrypt("harold@heroku.com".getBytes(UTF_8));
        String message = new String(new Fernet(secret).decrypt(token, null, Instant.now().plusSeconds(9999)), UTF_8);
        assertThat(message, is("harold@heroku.com"));
    }

    @Test
    @Ignore("there is no global config")
    public void can_ignore_TTL_enforcement_via_global_config() {
    }

    @Test
    public void does_not_send_the_message_in_plain_text() {
        final String token = new Fernet(secret).encrypt("password1".getBytes(UTF_8));
        assertThat(new String(Base64.getUrlDecoder().decode(token), UTF_8), not(containsString("password1")));
    }

    @Test
    @Ignore("not implemented")
    public void allows_overriding_enforce_ttl_on_a_verifier() {
    }

}
