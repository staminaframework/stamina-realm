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

import org.osgi.framework.BundleContext;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;

/**
 * Password hasher utilities.
 *
 * @author Stamina Framework developers
 */
final class PasswordHasherUtils {
    private PasswordHasherUtils() {
    }

    private static File getUserSaltFile(BundleContext bundleContext, String user, String hashAlgorithm) {
        requireNonNull(bundleContext, "Bundle context cannot be null");
        requireNonNull(user, "User cannot be null");
        requireNonNull(hashAlgorithm, "Hash algorithm cannot be null");
        return bundleContext.getDataFile("salt-" + hashAlgorithm + "-" + user + ".dat");
    }

    public static void resetUserSalt(BundleContext bundleContext, String user, String hashAlgorithm) {
        getUserSaltFile(bundleContext, user, hashAlgorithm).delete();
    }

    public static byte[] getUserSalt(BundleContext bundleContext, String user, String hashAlgorithm,
                                     int saltLength, SecureRandom secureRandom) throws IOException {
        final File userSaltFile = getUserSaltFile(bundleContext, user, hashAlgorithm);
        final byte[] salt = new byte[saltLength];
        boolean saltInitialized = false;
        if (userSaltFile.exists() && userSaltFile.length() == saltLength) {
            try (final FileInputStream in = new FileInputStream(userSaltFile)) {
                saltInitialized = saltLength == in.read(salt);
            }
        }

        if (!saltInitialized) {
            secureRandom.nextBytes(salt);
            try (final FileOutputStream out = new FileOutputStream(userSaltFile)) {
                out.getChannel().lock();
                out.write(salt);
            }
        }
        return salt;
    }
}
