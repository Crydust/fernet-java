package be.crydust.fernet;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.ZonedDateTime.now;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TokenMessageTest {
    private final String SECRET = "odN/0Yu+Pwp3oIvvG8OiE5w4LsLrqfWYRb3knQtSyKI=";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void refuses_to_decrypt_if_invalid() {
        final String generated = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8), now().plusSeconds(61));
        thrown.expect(FernetException.class);
        thrown.expectMessage("far-future TS (unacceptable clock skew)");
        new Fernet(SECRET).decrypt(generated);
    }

    @Test
    public void gives_back_the_original_message_in_plain_text() {
        final String token = new Fernet(SECRET).encrypt("hello".getBytes(UTF_8));
        assertThat(new String(new Fernet(SECRET).decrypt(token), UTF_8), is("hello"));
    }

    @Test
    public void correctly_handles_an_empty_message() {
        final String token = new Fernet(SECRET).encrypt("".getBytes(UTF_8));
        assertThat(new String(new Fernet(SECRET).decrypt(token), UTF_8), is(""));
    }
}
