import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import bitcoinjava.VarInt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class VarIntTest {
    @ParameterizedTest
    @MethodSource("testStreamParameters")
    public void fromByteStream(String hex, BigInteger expectedResult) throws IOException {
        assertEquals(
            expectedResult,
            VarInt.fromByteStream(new ByteArrayInputStream(Hex.decodeStrict(hex)))
        );
    }

    @ParameterizedTest
    @MethodSource("testStreamParameters")
    public void toByteStream(String expectedResult, BigInteger bigInteger) {
        assertEquals(
            expectedResult,
            VarInt.toHex(bigInteger)
        );
    }

    private static Stream<Arguments> testStreamParameters() {
        return Stream.of(
            Arguments.of(
                "64", BigInteger.valueOf(100)
            ),
            Arguments.of(
                "fdff00", BigInteger.valueOf(255)
            ),
            Arguments.of(
                "fd2b02", BigInteger.valueOf(555)
            ),
            Arguments.of(
                "fe7f110100", BigInteger.valueOf(70015)
            ),
            Arguments.of(
                "ff6dc7ed3e60100000", BigInteger.valueOf(18005558675309L)
            )
        );
    }

}
