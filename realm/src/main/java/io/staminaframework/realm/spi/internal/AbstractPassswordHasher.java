/*
 * Copyright (c) 2017 Stamina Framework developers.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.staminaframework.realm.spi.internal;

import io.staminaframework.realm.UserSession;
import io.staminaframework.realm.spi.PasswordHasher;
import org.osgi.framework.BundleContext;
import org.osgi.service.useradmin.UserAdminEvent;
import org.osgi.service.useradmin.UserAdminListener;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Abstract {@link PasswordHasher} implementation.
 * <p>
 * This implementation is using a randomly generated salt for each user.
 * This salt is used to secure password hashing operations.
 *
 * @author Stamina Framework developers
 */
abstract class AbstractPassswordHasher implements PasswordHasher, UserAdminListener {
    @interface Config {
        boolean useSalt() default true;
    }

    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private final String prefix;
    private final String algorithm;
    private final int saltLength;
    private BundleContext bundleContext;
    private SecureRandom secureRandom;
    private boolean useSalt = true;

    public AbstractPassswordHasher(final String prefix, final String algorithm, final int saltLength) {
        this.prefix = prefix;
        this.algorithm = algorithm;
        this.saltLength = saltLength;
    }

    @Override
    public String hash(String userId, String password) {
        final byte[] rawPassword;
        try {
            rawPassword = password.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            // Unlikely to happen: UTF-8 is required for every JVM implementation.
            return null;
        }

        final byte[] userSalt = salt(userId);
        final byte[] saltedPassword = new byte[rawPassword.length + userSalt.length];
        System.arraycopy(userSalt, 0, saltedPassword, 0, userSalt.length);
        System.arraycopy(rawPassword, 0, saltedPassword, userSalt.length, rawPassword.length);

        final MessageDigest md;
        try {
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            // This may happen if the algorithm is not available in the JVM implementation.
            return null;
        }
        final byte[] hash = md.digest(saltedPassword);
        return prefix + ":" + BASE64_ENCODER.encodeToString(hash);
    }

    private File getUserSaltFile(String user) {
        return bundleContext.getDataFile("salt-" + prefix + "-" + user + ".dat");
    }

    public byte[] salt(String user) {
        if (user == null || !useSalt) {
            return new byte[0];
        }
        final File userSaltFile = getUserSaltFile(user);
        final byte[] salt = new byte[saltLength];
        boolean saltInitialized = false;
        if (userSaltFile.exists()) {
            try (final DataInputStream in = new DataInputStream(new FileInputStream(userSaltFile))) {
                saltInitialized = saltLength == in.read(salt);
            } catch (IOException e) {
                return null;
            }
        }
        if (!saltInitialized) {
            secureRandom.nextBytes(salt);
            try (final DataOutputStream out = new DataOutputStream(new FileOutputStream(userSaltFile))) {
                out.write(salt);
            } catch (IOException e) {
                return null;
            }
        }
        return salt;
    }

    public void activate(BundleContext bundleContext, Config config) throws Exception {
        this.bundleContext = bundleContext;
        secureRandom = SecureRandom.getInstanceStrong();
        useSalt = config.useSalt();
    }

    public void deactivate() {
        bundleContext = null;
        secureRandom = null;
    }

    @Override
    public void roleChanged(UserAdminEvent event) {
        if (UserSession.ROLE_LOGGED_OUT == event.getType()) {
            final File userSaltFile = getUserSaltFile(event.getRole().getName());
            userSaltFile.delete();
        }
    }
}
