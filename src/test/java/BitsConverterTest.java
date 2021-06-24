import bitcoinjava.Bech32;
import bitcoinjava.BitsConverter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class BitsConverterTest {

    @ParameterizedTest
    @MethodSource("convertBitsParameters")
    public void converBitsTest(List<Integer> expectedList, String dataHex) {
        byte[] data = Hex.decode(dataHex);
        assertArrayEquals(expectedList.toArray(), BitsConverter.convertBits(data, 8, 5, true).toArray());
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

}
