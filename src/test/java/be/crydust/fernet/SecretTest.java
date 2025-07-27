package be.crydust.fernet;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class SecretTest {

    private static final String AX16_BX16 = Helper.repeat("A", 16) + Helper.repeat("B", 16);

    @Test
    void can_resolve_a_URL_safe_base64_encoded_32_byte_string() {
        final String encoded = Base64.getUrlEncoder().encodeToString(AX16_BX16.getBytes(UTF_8));
        resolves_input(encoded);
    }

    @Test
    void can_resolve_a_base64_encoded_32_byte_string() {
        resolves_input(Base64.getEncoder().encodeToString(AX16_BX16.getBytes(UTF_8)));
    }

    @Test
    void can_resolve_a_base64_encoded_32_byte_string_without_padding() {
        resolves_input(Base64.getEncoder().withoutPadding().encodeToString(AX16_BX16.getBytes(UTF_8)));
    }

    @Test
    void can_resolve_a_32_byte_string_without_encoding() {
        resolves_input(AX16_BX16);
    }

    @Test
    void fails_loudly_when_an_invalid_secret_is_provided() {
        final String secret = Base64.getUrlEncoder().encodeToString("bad".getBytes(UTF_8));
        assertThatExceptionOfType(FernetException.class)
                .isThrownBy(() -> new Fernet(secret))
                .withMessage("invalid secret");
    }

    @Test
    void fails_loudly_when_an_invalid_secret_is_provided_with_illegal_base64_char() {
        final String secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*=";
        assertThatExceptionOfType(FernetException.class)
                .isThrownBy(() -> new Fernet(secret))
                .withMessage("invalid secret");
    }

    private static void resolves_input(String input) {
        final byte[] keyBytes = Base64.getUrlDecoder().decode(new Fernet(input).toString());
        assertThat(new String(Arrays.copyOfRange(keyBytes, 0, 16), UTF_8)).isEqualTo(Helper.repeat("A", 16));
        assertThat(new String(Arrays.copyOfRange(keyBytes, 16, 32), UTF_8)).isEqualTo(Helper.repeat("B", 16));
    }

}
