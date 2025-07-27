package be.crydust.fernet;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class BitPackingTest {

    private static Stream<Arguments> data() {
        return Stream.of(
                Arguments.of(0x0000000000000000L, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00}),
                Arguments.of(0x00000000000000FFL, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF}),
                Arguments.of(0x000000FF00000000L, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00}),
                Arguments.of(0x00000000FF000000L, new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00}),
                Arguments.of(0xFF00000000000000L, new byte[]{(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00}),
                Arguments.of(0xFFFFFFFFFFFFFFFFL, new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF})
        );
    }

    @ParameterizedTest
    @MethodSource("data")
    void packLongBigEndian(long input, byte[] expected) {
        assertThat(Fernet.packLongBigEndian(input)).isEqualTo(expected);
    }

    @ParameterizedTest
    @MethodSource("data")
    void unpackLongBigEndian(long expected, byte[] input) {
        assertThat(Fernet.unpackLongBigEndian(input, 0, 8)).isEqualTo(expected);
    }
}
