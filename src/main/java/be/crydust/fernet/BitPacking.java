package be.crydust.fernet;

import java.nio.ByteBuffer;

final class BitPacking {
    private BitPacking() {
    }

    static byte[] packLongBigendian(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    static long unpackLongBigendian(byte[] bytes) {
        if (bytes.length != 8) {
            throw new IllegalArgumentException("Expected an array of 8 bytes, not " + bytes.length);
        }
        return ByteBuffer.wrap(bytes).getLong();
    }
}
