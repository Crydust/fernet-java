package be.crydust.fernet;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import javax.crypto.spec.IvParameterSpec;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class SpecificationTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void generate() throws Exception {
        try (final InputStream in = SpecificationTest.class.getResourceAsStream("generate.json")) {
            final JSONObject object = new JSONArray(new JSONTokener(in)).getJSONObject(0);
            final String expectedToken = object.getString("token");
            final String nowString = object.getString("now");
            final ZonedDateTime now = ZonedDateTime.parse(nowString, DateTimeFormatter.ISO_ZONED_DATE_TIME);
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
            assertThat(actualToken, is(expectedToken));
        }
    }

    @Test
    public void verify() throws Exception {
        try (final InputStream in = SpecificationTest.class.getResourceAsStream("verify.json")) {
            final JSONObject object = new JSONArray(new JSONTokener(in)).getJSONObject(0);
            final String actualToken = object.getString("token");
            final String nowString = object.getString("now");
            final ZonedDateTime now = ZonedDateTime.parse(nowString, DateTimeFormatter.ISO_ZONED_DATE_TIME);
            final long ttl = object.getLong("ttl_sec");
            final String expectedMessage = object.getString("src");
            final String secretString = object.getString("secret");
            final byte[] decryptedBytes = new Fernet(secretString).decrypt(actualToken, Duration.ofSeconds(ttl), now);
            final String actualMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
            assertThat(actualMessage, is(expectedMessage));
        }
    }

    @Test
    public void invalid() throws Exception {
        try (final InputStream in = SpecificationTest.class.getResourceAsStream("invalid.json")) {
            final JSONArray array = new JSONArray(new JSONTokener(in));
            for (int i = 0; i < array.length(); i++) {
                final JSONObject object = array.getJSONObject(i);
                final String desc = object.getString("desc");
                final String expectedMessage = desc.equals("incorrect IV (causes padding error)")
                        ? "payload padding error" : desc;
                final String actualToken = object.getString("token");
                final String nowString = object.getString("now");
                final ZonedDateTime now = ZonedDateTime.parse(nowString, DateTimeFormatter.ISO_ZONED_DATE_TIME);
                final long ttl = object.getLong("ttl_sec");
                final String secretString = object.getString("secret");
                thrown.expect(FernetException.class);
                thrown.expectMessage(expectedMessage);
                new Fernet(secretString).decrypt(actualToken, Duration.ofSeconds(ttl), now);
            }
        }
    }

}
