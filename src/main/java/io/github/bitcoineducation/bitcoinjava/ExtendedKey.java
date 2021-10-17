package io.github.bitcoineducation.bitcoinjava;

import java.math.BigInteger;

public interface ExtendedKey {
    ExtendedKey ckd(BigInteger index, boolean isPrivate, boolean isHardened, String prefix);

    String serialize();

    PublicKey toPublicKey();
}
