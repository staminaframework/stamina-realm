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
import org.osgi.service.useradmin.Authorization;
import org.osgi.service.useradmin.User;

/**
 * User session interface.
 *
 * @author Stamina Framework developers
 */
@ConsumerType
public interface UserSession extends Authorization {
    /**
     * {@link org.osgi.service.useradmin.UserAdminEvent} type used
     * when an user session is made invalid.
     */
    int ROLE_LOGGED_OUT = 0x00000016;

    /**
     * Invalid this session.
     * Calling this method on an invalid session has no effect.
     * Registered {@link org.osgi.service.useradmin.UserAdminListener} services
     * will be notified when this method is called, using event type {@link #ROLE_LOGGED_OUT}.
     * If <code>Event-Admin</code> is available, an event will be fired using topic
     * <code>org/osgi/service/useradmin/UserAdmin/ROLE_LOGGED_OUT</code>, just like other events.
     */
    void invalid();

    /**
     * Get session validity.
     * This session is made invalid if method {@link #invalid()} is called.
     *
     * @return <code>true</code> if this session is still valid
     */
    boolean isValid();

    /**
     * Check if this session was fully authenticated.
     * A session is authenticated if user identity was verified with its credentials,
     * using method {@link UserSessionAdmin#authenticate(String, Object...)}.
     * If this instance is the result of calling
     * {@link org.osgi.service.useradmin.UserAdmin#getAuthorization(User)}, this session
     * will not be treated as authenticated.
     *
     * @return <code>true</code> if user credentials have been verified
     */
    boolean isAuthenticated();
}
