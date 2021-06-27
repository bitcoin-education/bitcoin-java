package bitcoinjava;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public interface ExtendedKey {
    ExtendedKey ckd(BigInteger index, boolean isPrivate, boolean isHardened, String environment) throws NoSuchAlgorithmException;

    String serialize() throws NoSuchAlgorithmException;
}
