package be.crydust.fernet;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class BitPackingTest {
    private static final Map<Long, byte[]> VALUE_TO_BYTES = new HashMap<>();

    static {
        VALUE_TO_BYTES.put(0x0000000000000000L, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        VALUE_TO_BYTES.put(0x00000000000000FFL, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF});
        VALUE_TO_BYTES.put(0x000000FF00000000L, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        VALUE_TO_BYTES.put(0x00000000FF000000L, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        VALUE_TO_BYTES.put(0xFF00000000000000L, new byte[]{(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        VALUE_TO_BYTES.put(0xFFFFFFFFFFFFFFFFL, new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
    }

    @Test
    public void packLongBigEndian() {
        for (Map.Entry<Long, byte[]> entry : VALUE_TO_BYTES.entrySet()) {
            assertThat(Fernet.packLongBigEndian(entry.getKey()), is(entry.getValue()));
        }
    }

    @Test
    public void unpackLongBigEndian() {
        for (Map.Entry<Long, byte[]> entry : VALUE_TO_BYTES.entrySet()) {
            assertThat(Fernet.unpackLongBigEndian(entry.getValue(), 0, 8), is(entry.getKey()));
        }
    }
}
