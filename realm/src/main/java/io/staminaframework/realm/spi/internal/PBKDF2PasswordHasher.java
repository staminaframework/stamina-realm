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


import io.staminaframework.realm.spi.PasswordHasher;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.useradmin.Role;
import org.osgi.service.useradmin.UserAdminEvent;
import org.osgi.service.useradmin.UserAdminListener;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * {@link PasswordHasher} implementation using
 * <i>Password-Based Key Derivation Function 2</i> algorithm.
 *
 * @author Stamina Framework developers
 */
@Component(service = {PasswordHasher.class, UserAdminListener.class},
        property = {PasswordHasher.HASH_TYPE + "=pbkdf2", Constants.SERVICE_RANKING + ":Integer=500"},
        configurationPid = "io.staminaframework.realm.pbkdf2")
public class PBKDF2PasswordHasher implements PasswordHasher, UserAdminListener {
    /**
     * Component configuration.
     */
    @interface Config {
        /**
         * Get key length.
         */
        int keyLength() default 256;

        /**
         * Get algorithm iterations.
         */
        int iterations() default 500;

        /**
         * Get PBKDF2 algorithm.
         */
        String algorithm() default "PBKDF2WithHmacSHA512";
    }

    @Reference(target = "(provider=stamina-realm)")
    private SecureRandom secureRandom;
    private BundleContext bundleContext;
    private int keyLength;
    private int iterations;
    private String algorithm;

    @Activate
    public void activate(BundleContext bundleContext, Config config) {
        this.bundleContext = bundleContext;
        keyLength = config.keyLength();
        iterations = config.iterations();
        algorithm = config.algorithm();
    }

    @Deactivate
    public void deactivate() {
        bundleContext = null;
    }

    @Override
    public String hash(String user, String password) throws Exception {
        final SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
        final byte[] salt = PasswordHasherUtils.getUserSalt(bundleContext, user, "pbkdf2", keyLength, secureRandom);
        final PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        final SecretKey key = skf.generateSecret(spec);
        final byte[] hashedPassword = key.getEncoded();
        return Base64.getEncoder().encodeToString(hashedPassword);
    }

    @Override
    public void roleChanged(UserAdminEvent event) {
        if (event.getType() == UserAdminEvent.ROLE_REMOVED && event.getRole().getType() == Role.USER) {
            PasswordHasherUtils.resetUserSalt(bundleContext, event.getRole().getName(), "pbkdf2");
        }
    }
}
