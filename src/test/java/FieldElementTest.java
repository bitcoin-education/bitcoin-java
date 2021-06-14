import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static java.math.BigInteger.valueOf;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class FieldElementTest {

    @ParameterizedTest()
    @MethodSource("testAddParameters")
    public void testAdd(FieldElement a, FieldElement b, FieldElement expectedResult) {
        assertEquals(expectedResult, a.add(b));
    }

    private static Stream<Arguments> testAddParameters() {
        return Stream.of(
            Arguments.of(new FieldElement(valueOf(44), valueOf(57)), new FieldElement(valueOf(33), valueOf(57)), new FieldElement(valueOf(20), valueOf(57)))
        );
    }
}
