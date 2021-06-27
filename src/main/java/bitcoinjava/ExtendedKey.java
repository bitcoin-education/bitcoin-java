package bitcoinjava;

import java.math.BigInteger;

public interface ExtendedKey {
    ExtendedKey ckd(BigInteger index, boolean isPrivate, boolean isHardened, String environment);

    String serialize();

    PublicKey toPublicKey();
}
