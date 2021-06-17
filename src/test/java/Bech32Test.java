import bitcoinjava.Bech32;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import static java.math.BigInteger.valueOf;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class Bech32Test {
    @ParameterizedTest
    @MethodSource("convertBitsParameters")
    public void converBitsTest(List<Integer> expectedList, String witnessProgram) {
        byte[] witnessProgramBytes = Hex.decode(witnessProgram);
        assertArrayEquals(expectedList.toArray(), Bech32.convertBits(witnessProgramBytes).toArray());
    }

    @ParameterizedTest
    @MethodSource("hrpExpandParameters")
    public void hrpExpandTest(List<Integer> expectedList, String hrp) {
        assertArrayEquals(expectedList.toArray(), Bech32.hrpExpand(hrp).toArray());
    }

    @ParameterizedTest
    @MethodSource("polymodParameters")
    public void polymodTest(BigInteger expectedResult, List<Integer> values) {
        assertEquals(expectedResult, Bech32.polymod(values));
    }

    @ParameterizedTest
    @MethodSource("createChecksumParameters")
    public void createChecksumTest(String hrp, List<Integer> data, List<Integer> expectedResult) {
        assertEquals(expectedResult, Bech32.createChecksum(hrp, data));
    }

    @ParameterizedTest
    @MethodSource("encodeParameters")
    public void encodeTest(String hrp, int witnessVersion, String witnessProgram, String expectedAddress) {
        assertEquals(expectedAddress, Bech32.encode(hrp, witnessVersion, Hex.decode(witnessProgram)));
    }

    private static Stream<Arguments> convertBitsParameters() {
        return Stream.of(
            Arguments.of(
                List.of(14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22),
                "751e76e8199196d454941c45d1b3a323f1433bd6"
            ),
            Arguments.of(
                List.of(3, 1, 17, 17, 8, 15, 0, 20, 24, 20, 11, 6, 16, 1, 5, 29, 3, 4, 16, 3, 6, 21, 22, 26, 2, 13, 22, 9, 16, 21, 19, 24, 25, 21, 6, 18, 15, 8, 13, 24, 24, 24, 25, 9, 12, 1, 4, 16, 6, 9, 17, 0),
                "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
            ),
            Arguments.of(
                List.of(15, 6, 31, 6, 12, 31, 23, 25, 27, 18, 29, 26, 24, 21, 13, 0, 12, 10, 10, 28, 29, 1, 24, 11, 0, 28, 1, 9, 23, 31, 6, 27, 5, 23, 7, 2, 17, 22, 10, 25, 30, 10, 0, 21, 22, 5, 23, 24, 2, 30, 12, 0),
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ),
            Arguments.of(
                List.of(14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22),
                "751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"
            ),
            Arguments.of(
                List.of(14, 20, 15, 0),
                "751e"
            ),
            Arguments.of(
                List.of(14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 12),
                "751e76e8199196d454941c45d1b3a323"
            )
        );
    }

    private static Stream<Arguments> hrpExpandParameters() {
        return Stream.of(
            Arguments.of(
                List.of(3, 3, 0, 2, 3),
                "bc"
            ),
            Arguments.of(
                List.of(3, 3, 0, 20, 3),
                "tc"
            ),
            Arguments.of(
                List.of(3, 3, 0, 20, 2),
                "tb"
            ),
            Arguments.of(
                List.of(3, 3, 3, 3, 3, 3, 0, 1, 2, 3, 4, 5, 6),
                "abcdef"
            )
        );
    }

    private static Stream<Arguments> polymodParameters() {
        return Stream.of(
            Arguments.of(
                valueOf(734539939),
                List.of(3, 3, 0, 20, 3, 1, 15, 6, 31, 6, 12, 31, 23, 25, 27, 18, 29, 26, 24, 21, 13, 0, 12, 10, 10, 28, 29, 1, 24, 11, 0, 28, 1, 9, 23, 31, 6, 27, 5, 23, 7, 2, 17, 22, 10, 25, 30, 10, 0, 21, 22, 5, 23, 24, 2, 30, 12, 0, 20, 2, 28, 4, 28, 11)
            ),
            Arguments.of(
                valueOf(167673071),
                List.of(3, 3, 0, 2, 3, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            ),
            Arguments.of(
                valueOf(804056987),
                List.of(3, 0, 13, 12, 28, 6, 14, 25, 2)
            ),
            Arguments.of(
                valueOf(1),
                List.of(3, 3, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 5, 1, 25, 24, 3)
            ),
            Arguments.of(
                valueOf(609281794),
                List.of(3, 3, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            )
        );
    }

    private static Stream<Arguments> createChecksumParameters() {
        return Stream.of(
            Arguments.of(
                "tb",
                List.of(0, 3, 1, 17, 17, 8, 15, 0, 20, 24, 20, 11, 6, 16, 1, 5, 29, 3, 4, 16, 3, 6, 21, 22, 26, 2, 13, 22, 9, 16, 21, 19, 24, 25, 21, 6, 18, 15, 8, 13, 24, 24, 24, 25, 9, 12, 1, 4, 16, 6, 9, 17, 0),
                List.of(15, 16, 31, 20, 22, 30)
            ),
            Arguments.of(
                "bc",
                List.of(0, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22),
                List.of(12, 7, 9, 17, 11, 21)
            ),
            Arguments.of(
                "bc",
                List.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                List.of(18, 5, 1, 25, 24, 3)
            ),
            Arguments.of(
                "BC",
                List.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                List.of(21, 10, 16, 28, 30, 14)
            )
        );
    }

    private static Stream<Arguments> encodeParameters() {
        return Stream.of(
            Arguments.of(
                "tb",
                0,
                "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
                "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy"
            ),
            Arguments.of(
                "tb",
                0,
                "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
            ),
            Arguments.of(
                "bc",
                0,
                "751e76e8199196d454941c45d1b3a323f1433bd6",
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT)
            )
        );
    }

}
