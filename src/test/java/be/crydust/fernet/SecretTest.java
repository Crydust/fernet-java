package be.crydust.fernet;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class SecretTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private static final String Ax16_Bx16 = Helper.repeat("A", 16) + Helper.repeat("B", 16);

    @Test
    public void can_resolve_a_URL_safe_base64_encoded_32_byte_string() {
        final String encoded = Base64.getUrlEncoder().encodeToString(Ax16_Bx16.getBytes(UTF_8));
        resolves_input(encoded);
    }

    @Test
    public void can_resolve_a_base64_encoded_32_byte_string() {
        resolves_input(Base64.getEncoder().encodeToString(Ax16_Bx16.getBytes(UTF_8)));
    }

    @Test
    public void can_resolve_a_base64_encoded_32_byte_string_without_padding() {
        resolves_input(Base64.getEncoder().withoutPadding().encodeToString(Ax16_Bx16.getBytes(UTF_8)));
    }

    @Test
    public void can_resolve_a_32_byte_string_without_encoding() {
        resolves_input(Ax16_Bx16);
    }

    @Test
    public void fails_loudly_when_an_invalid_secret_is_provided() {
        final String secret = Base64.getUrlEncoder().encodeToString("bad".getBytes(UTF_8));
        thrown.expect(FernetException.class);
        thrown.expectMessage("invalid secret");
        new Fernet(secret);
    }

    @Test
    public void fails_loudly_when_an_invalid_secret_is_provided_with_illegal_base64_char() {
        final String secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*=";
        thrown.expect(FernetException.class);
        thrown.expectMessage("invalid secret");
        new Fernet(secret);
    }

    private static void resolves_input(String input) {
        final byte[] keyBytes = Base64.getUrlDecoder().decode(new Fernet(input).toString());
        assertThat(new String(Arrays.copyOfRange(keyBytes, 0, 16), UTF_8), is(Helper.repeat("A", 16)));
        assertThat(new String(Arrays.copyOfRange(keyBytes, 16, 32), UTF_8), is(Helper.repeat("B", 16)));
    }

}
