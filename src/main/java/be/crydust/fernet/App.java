package be.crydust.fernet;


import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class App {
    public static void main(String[] args) throws Exception {
        generate();
        verify();
        invalid();
    }

    private static void generate() throws Exception {
        try (final InputStream in = App.class.getResourceAsStream("/generate.json")) {
            final JSONArray array = new JSONArray(new JSONTokener(in));
            final JSONObject object = array.getJSONObject(0);

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

            final Key key = new Key(secretString);
            final Token token = new Token(now, iv, message, key);
            final String actualToken = token.toString();

            System.out.println("expectedToken = " + expectedToken);
            System.out.println("actualToken =   " + actualToken);

            assert expectedToken.equals(actualToken);
        }
    }

    private static void verify() throws Exception {
        try (final InputStream in = App.class.getResourceAsStream("/verify.json")) {
            final JSONArray array = new JSONArray(new JSONTokener(in));
            final JSONObject object = array.getJSONObject(0);

            final String actualToken = object.getString("token");

            final String nowString = object.getString("now");
            final ZonedDateTime now = ZonedDateTime.parse(nowString, DateTimeFormatter.ISO_ZONED_DATE_TIME);

            final long ttl = object.getLong("ttl_sec");

            final String expectedMessage = object.getString("src");

            final String secretString = object.getString("secret");

            final Key key = new Key(secretString);

            final Token decryptedToken = Token.decrypt(now, actualToken, key, ttl);
            final String actualMessage = new String(decryptedToken.getMessage(), StandardCharsets.UTF_8);

            System.out.println("expectedMessage = " + expectedMessage);
            System.out.println("actualMessage =   " + actualMessage);

            assert expectedMessage.equals(actualMessage);
        }
    }

    private static void invalid() throws Exception {
        try (final InputStream in = App.class.getResourceAsStream("/invalid.json")) {
            final JSONArray array = new JSONArray(new JSONTokener(in));
            for (int i = 0; i < array.length(); i++) {
                final JSONObject object = array.getJSONObject(i);

                System.out.println("---------------------------");

                final String desc = object.getString("desc");

                System.out.println("i = " + i);
                System.out.println("desc = " + desc);


                final String actualToken = object.getString("token");

                final String nowString = object.getString("now");
                final ZonedDateTime now = ZonedDateTime.parse(nowString, DateTimeFormatter.ISO_ZONED_DATE_TIME);

                final long ttl = object.getLong("ttl_sec");

                final String secretString = object.getString("secret");

                final Key key = new Key(secretString);

                Thread.sleep(20);
                try {
                    final Token decryptedToken = Token.decrypt(now, actualToken, key, ttl);
                    throw new RuntimeException("ERROR exception not thrown");
                } catch (Exception e) {
                    if (desc.equals(e.getMessage())
                            || (desc.equals("incorrect IV (causes padding error)") && "payload padding error".equals(e.getMessage()))
                            ) {
                        System.out.println("OK expected message was " + desc);
                    } else {
                        throw e;
                    }
                }
                System.out.println("---------------------------");
            }
        }
    }

}
