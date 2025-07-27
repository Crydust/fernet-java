package be.crydust.fernet;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class SpecificationTest {

    @Test
    void generate() throws Exception {
        try (final InputStream in = SpecificationTest.class.getResourceAsStream("generate.json")) {
            final JSONObject object = new JSONArray(new JSONTokener(in)).getJSONObject(0);
            final String expectedToken = object.getString("token");
            final String nowString = object.getString("now");
            final Instant now = ZonedDateTime.parse(nowString, DateTimeFormatter.ISO_ZONED_DATE_TIME).toInstant();
            final JSONArray ivIntArray = object.getJSONArray("iv");
            final int ivLength = ivIntArray.length();
            if (ivLength != 16) {
                throw new RuntimeException("bad iv length " + ivLength);
            }
            final byte[] ivBytes = new byte[16];
            for (int i = 0; i < ivLength; i++) {
                ivBytes[i] = (byte) ivIntArray.getInt(i);
            }
            final IvParameterSpec iv = new IvParameterSpec(ivBytes);
            final String srcString = object.getString("src");
            final byte[] message = srcString.getBytes(StandardCharsets.UTF_8);
            final String secretString = object.getString("secret");
            final String actualToken = new Fernet(secretString).encrypt(message, iv, now);
            assertThat(actualToken).isEqualTo(expectedToken);
        }
    }

    @Test
    void verify() throws Exception {
        try (final InputStream in = SpecificationTest.class.getResourceAsStream("verify.json")) {
            final JSONObject object = new JSONArray(new JSONTokener(in)).getJSONObject(0);
            final String actualToken = object.getString("token");
            final String nowString = object.getString("now");
            final Instant now = ZonedDateTime.parse(nowString, DateTimeFormatter.ISO_ZONED_DATE_TIME).toInstant();
            final long ttl = object.getLong("ttl_sec");
            final String expectedMessage = object.getString("src");
            final String secretString = object.getString("secret");
            final byte[] decryptedBytes = new Fernet(secretString).decrypt(actualToken, Duration.ofSeconds(ttl), now);
            final String actualMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
            assertThat(actualMessage).isEqualTo(expectedMessage);
        }
    }

    @Test
    void invalid() throws Exception {
        try (final InputStream in = SpecificationTest.class.getResourceAsStream("invalid.json")) {
            final JSONArray array = new JSONArray(new JSONTokener(in));
            for (int i = 0; i < array.length(); i++) {
                final JSONObject object = array.getJSONObject(i);
                final String desc = object.getString("desc");
                final String expectedMessage = desc.equals("incorrect IV (causes padding error)")
                        ? "payload padding error" : desc;
                final String actualToken = object.getString("token");
                final String nowString = object.getString("now");
                final Instant now = ZonedDateTime.parse(nowString, DateTimeFormatter.ISO_ZONED_DATE_TIME).toInstant();
                final long ttl = object.getLong("ttl_sec");
                final String secretString = object.getString("secret");
                assertThatExceptionOfType(FernetException.class)
                        .isThrownBy(() -> new Fernet(secretString).decrypt(actualToken, Duration.ofSeconds(ttl), now))
                        .withMessage(expectedMessage);
            }
        }
    }

}
