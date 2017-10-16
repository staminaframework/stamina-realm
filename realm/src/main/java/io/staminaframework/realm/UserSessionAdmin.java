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

package io.staminaframework.realm;

import org.osgi.annotation.versioning.ConsumerType;

/**
 * Service interface for creating user sessions.
 *
 * @author Stamina Framework developers
 */
@ConsumerType
public interface UserSessionAdmin {
    /**
     * Authenticate an user using its credentials.
     * Use methods from {@link UserCredentials} to create user credentials.
     * An user may hold several credentials: all credentials are required to authenticate
     * a session.
     *
     * @param user        user id
     * @param credentials user credentials
     * @return a user session if authentication was successful, <code>null</code> otherwise
     */
    UserSession authenticate(String user, Object... credentials);
}
