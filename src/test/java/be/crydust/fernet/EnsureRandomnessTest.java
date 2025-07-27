package be.crydust.fernet;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

class EnsureRandomnessTest {

    @Test
    void key_is_not_all_zeroes() {
        final byte[] keyBytes = Base64.getUrlDecoder().decode(new Fernet().toString());
        assertThat(keyBytes).isNotEqualTo(new byte[]{
                (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0});
    }

    @Test
    void iv_is_not_all_zeroes() {
        final String token = new Fernet().encrypt(new byte[0]);
        final byte[] tokenBytes = Base64.getUrlDecoder().decode(token);
        final byte[] ivBytes = Arrays.copyOfRange(tokenBytes, 1 + 8, 1 + 8 + 16);
        assertThat(ivBytes).isNotEqualTo(new byte[]{
                (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0});
    }

    @Test
    void is_fully_serialized_by_toString() {
        final Fernet original = new Fernet();
        final Fernet copy = new Fernet(original.toString());
        final String encrypted = original.encrypt("hello".getBytes(UTF_8));
        assertThat(new String(copy.decrypt(encrypted), UTF_8)).isEqualTo("hello");
    }

}
