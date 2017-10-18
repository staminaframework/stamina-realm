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
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;

/**
 * Plain text password hasher.
 *
 * @author Stamina Framework developers
 */
@Component(service = PasswordHasher.class,
        property = {PasswordHasher.HASH_TYPE + "=plaintext", Constants.SERVICE_RANKING + ":Integer=0"})
public class PlainTextPasswordHasher implements PasswordHasher {
    @Override
    public String hash(String user, String password) {
        return password;
    }
}
