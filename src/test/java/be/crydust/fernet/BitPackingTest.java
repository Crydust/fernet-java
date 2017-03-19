package be.crydust.fernet;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class BitPackingTest {
    static Map<Long, byte[]> VALUE_TO_BYTES = new HashMap<>();

    static {
        VALUE_TO_BYTES.put(0x0000000000000000L, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        VALUE_TO_BYTES.put(0x00000000000000FFL, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF});
        VALUE_TO_BYTES.put(0x000000FF00000000L, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        VALUE_TO_BYTES.put(0x00000000FF000000L, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        VALUE_TO_BYTES.put(0xFF00000000000000L, new byte[]{(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        VALUE_TO_BYTES.put(0xFFFFFFFFFFFFFFFFL, new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
    }

    @Test
    public void packLongBigendian() throws Exception {
        for (Map.Entry<Long, byte[]> entry : VALUE_TO_BYTES.entrySet()) {
            assertThat(BitPacking.packLongBigendian(entry.getKey()), is(entry.getValue()));
        }
    }

    @Test
    public void unpackLongBigendian() throws Exception {
        for (Map.Entry<Long, byte[]> entry : VALUE_TO_BYTES.entrySet()) {
            assertThat(BitPacking.unpackLongBigendian(entry.getValue()), is(entry.getKey()));
        }
    }
}
