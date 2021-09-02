package io.github.bitcoineducation.bitcoinjava;

import java.math.BigInteger;

public interface ExtendedKey {
    ExtendedKey ckd(BigInteger index, boolean isPrivate, boolean isHardened);

    String serialize();

    PublicKey toPublicKey();
}
