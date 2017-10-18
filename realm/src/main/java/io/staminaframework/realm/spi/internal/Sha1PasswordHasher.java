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
import org.osgi.service.useradmin.UserAdminListener;

/**
 * {@link PasswordHasher} implementation using SHA-1 algorithm.
 *
 * @author Stamina Framework developers
 */
@Component(service = {PasswordHasher.class, UserAdminListener.class},
        property = {PasswordHasher.HASH_TYPE + "=sha1", Constants.SERVICE_RANKING + ":Integer=160"},
        configurationPid = "io.staminaframework.realm")
public class Sha1PasswordHasher extends AbstractPassswordHasher {
    public Sha1PasswordHasher() {
        super("sha1", "SHA-1", 160);
    }

    @Activate
    public void activate(BundleContext bundleContext, Config config) throws Exception {
        super.activate(bundleContext, config);
    }

    @Deactivate
    public void deactivate() {
        super.deactivate();
    }
}
