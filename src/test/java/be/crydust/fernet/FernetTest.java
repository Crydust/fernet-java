package be.crydust.fernet;

import org.junit.Test;

import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class FernetTest {
    String secret = "JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=";
    String bad_secret = "badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=";

    @Test
    public void can_verify_tokens_it_generates() throws Exception {
        Stream.of("harold@heroku.com", "12345", "weird!@#$%^&*()chars", "more weird chars §§§§").forEach(plain -> {
            String token = new Token(plain.getBytes(UTF_8), new Key(secret)).toString();
            String message = new String(Token.decrypt(token, new Key(secret)).getMessage(), UTF_8);
            assertThat(message, is(plain));
        });
    }
}
