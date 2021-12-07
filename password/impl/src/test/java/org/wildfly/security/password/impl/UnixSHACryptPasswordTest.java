package org.wildfly.security.password.impl;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.UnixSHACryptPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;

import java.security.Provider;
import java.security.Security;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class UnixSHACryptPasswordTest {

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testBasicFunctionality() throws Exception {
        String password = "test_password";
        String salt = "saltstring";
        int iterationCount = 1200;

        PasswordFactory passwordFactory = PasswordFactory.getInstance(UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_256);
        IteratedSaltedPasswordAlgorithmSpec algorithmSpec = new IteratedSaltedPasswordAlgorithmSpec(iterationCount, salt.getBytes(UTF_8));
        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(password.toCharArray(), algorithmSpec);
        UnixSHACryptPassword unixSHACryptPassword = (UnixSHACryptPassword) passwordFactory.generatePassword(encryptableSpec);

        assertArrayEquals("Salt correctly passed", salt.getBytes(UTF_8), unixSHACryptPassword.getSalt());
        assertEquals("Iteration count correctly passed", iterationCount, unixSHACryptPassword.getIterationCount());

        assertTrue(passwordFactory.verify(unixSHACryptPassword, password.toCharArray()));
    }

    @Test
    public void testTranslateFunctionality() throws Exception {
        String password = "test_password";
        String salt = "saltstring";
        int iterationCount = 1200;
        int updatedIterationCount = 1300;

        IteratedSaltedPasswordAlgorithmSpec algorithmSpec = new IteratedSaltedPasswordAlgorithmSpec(iterationCount, salt.getBytes(UTF_8));
        IteratedSaltedPasswordAlgorithmSpec updatedIterationAlgorithmSpec = new IteratedSaltedPasswordAlgorithmSpec(updatedIterationCount, salt.getBytes(UTF_8));

        PasswordFactory passwordFactory = PasswordFactory.getInstance(UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_256);

        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(password.toCharArray(), algorithmSpec);
        UnixSHACryptPassword unixSHACryptPassword = (UnixSHACryptPassword) passwordFactory.generatePassword(encryptableSpec);

        assertArrayEquals("Salt correctly passed", salt.getBytes(UTF_8), unixSHACryptPassword.getSalt());
        assertEquals("Iteration count correctly passed", iterationCount, unixSHACryptPassword.getIterationCount());

        encryptableSpec = new EncryptablePasswordSpec(password.toCharArray(), updatedIterationAlgorithmSpec);
        UnixSHACryptPassword unixSHACryptPasswordUpdatedSequence = (UnixSHACryptPassword) passwordFactory.generatePassword(encryptableSpec);
        UnixSHACryptPassword unixSHACryptPasswordTranslated = (UnixSHACryptPassword) passwordFactory.transform(unixSHACryptPassword, encryptableSpec);

        assertArrayEquals("Hashes should be same", unixSHACryptPasswordUpdatedSequence.getHash(), unixSHACryptPasswordTranslated.getHash());
    }
}
