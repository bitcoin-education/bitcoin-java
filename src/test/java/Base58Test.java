import bitcoinjava.Base58;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.Security;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Base58Test {
    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @MethodSource("encodeTestParameters")
    public void encodeTest(String hexString, String expectedResult) {
        assertEquals(Base58.encodeFromHex(hexString), expectedResult);
    }

    @Test
    public void decodeTest() {
        String hexString = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs";
        String expectedResult = "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31";
        assertEquals(expectedResult, Base58.decodeWithChecksumToHex(hexString));
    }

    private static Stream<Arguments> encodeTestParameters() {
        return Stream.of(
            Arguments.of(
                "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
                "9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6"
            ),
            Arguments.of(
                "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c",
                "4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd"
            ),
            Arguments.of(
                "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6",
                "EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7"
            )
        );
    }

}
