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
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.log.LogService;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Dictionary;
import java.util.Hashtable;

/**
 * This component registers a {@link SecureRandom} implementation to the Service Registry.
 * The registered instance has a service property <code>provider</code>
 * with value <code>stamina-realm</code>.
 *
 * @author Stamina Framework developers
 */
@Component(configurationPid = "io.staminaframework.realm.rng")
public class SecureRandomFactory {
    @Reference
    private LogService logService;
    private ServiceRegistration<SecureRandom> reg;

    @interface Config {
        String rngAlgorithm() default "default";
    }

    private SecureRandom createSecureRandom(String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case "default":
                return new SecureRandom();
            case "strong":
                return SecureRandom.getInstanceStrong();
            default:
                return SecureRandom.getInstance(algorithm);
        }
    }

    @Activate
    public void activate(BundleContext bundleContext, Config config) throws NoSuchAlgorithmException {
        final SecureRandom secureRandom = createSecureRandom(config.rngAlgorithm());

        logService.log(LogService.LOG_INFO,
                "Using SecureRandom " + secureRandom.getAlgorithm()
                        + " provided by " + secureRandom.getProvider());
        final Dictionary<String, Object> props = new Hashtable<>(2);
        props.put("algorithm", secureRandom.getAlgorithm());
        props.put("provider", "stamina-realm");
        reg = bundleContext.registerService(SecureRandom.class, secureRandom, props);
    }

    @Deactivate
    public void deactivate() {
        if (reg != null) {
            reg.unregister();
            reg = null;
        }
    }
}
