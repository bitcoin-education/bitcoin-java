import java.math.BigInteger;
import java.util.Objects;

public class FieldElement {
    private final BigInteger number;

    private final BigInteger prime;

    public FieldElement(BigInteger number, BigInteger prime) {
        if (number.compareTo(prime) >= 0 || number.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException("Number not in field range 0 to ".concat(prime.toString()));
        }
        this.number = number;
        this.prime = prime;
    }

    public FieldElement add(FieldElement fieldElement) {
        if (!prime.equals(fieldElement.getPrime())) {
            throw new IllegalArgumentException("Cannot add two numbers in different fields".concat(prime.toString()));
        }
        BigInteger resultingNumber = number.add(fieldElement.getNumber()).mod(prime);
        return new FieldElement(resultingNumber, prime);
    }

    public BigInteger getNumber() {
        return number;
    }

    public BigInteger getPrime() {
        return prime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FieldElement that = (FieldElement) o;
        return number.equals(that.number) && prime.equals(that.prime);
    }

    @Override
    public int hashCode() {
        return Objects.hash(number, prime);
    }

    @Override
    public String toString() {
        return "FieldElement{" +
            "number=" + number +
            ", prime=" + prime +
            '}';
    }
}
