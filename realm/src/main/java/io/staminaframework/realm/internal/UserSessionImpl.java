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

package io.staminaframework.realm.internal;

import io.staminaframework.realm.UserSession;

import java.util.Arrays;

/**
 * {@link UserSession} implementation.
 *
 * @author Stamina Framework developers
 */
final class UserSessionImpl implements UserSession {
    private final UserSessionAdminImpl usa;
    private final UserImpl user;
    private boolean valid = true;
    private final boolean authenticated;
    private final String[] groups;

    public UserSessionImpl(final UserSessionAdminImpl usa, final UserImpl user,
                           final String[] groups, final boolean authenticated) {
        this.usa = usa;
        this.user = user;
        this.groups = groups;
        this.authenticated = authenticated;
    }

    @Override
    public void invalid() {
        final boolean stateChanged = valid;
        valid = false;

        if (stateChanged) {
            usa.notifyUserAdminListeners(UserSession.ROLE_LOGGED_OUT, user);
        }
    }

    @Override
    public boolean isValid() {
        return valid;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public String getName() {
        return user.getName();
    }

    @Override
    public boolean hasRole(String name) {
        if (groups != null) {
            for (final String group : groups) {
                if (group.equals(name)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public String[] getRoles() {
        return groups;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        UserSessionImpl that = (UserSessionImpl) o;

        if (valid != that.valid) return false;
        if (authenticated != that.authenticated) return false;
        if (!user.equals(that.user)) return false;
        // Probably incorrect - comparing Object[] arrays with Arrays.equals
        return Arrays.equals(groups, that.groups);
    }

    @Override
    public int hashCode() {
        int result = user.hashCode();
        result = 31 * result + (valid ? 1 : 0);
        result = 31 * result + (authenticated ? 1 : 0);
        result = 31 * result + Arrays.hashCode(groups);
        return result;
    }

    @Override
    public String toString() {
        return "UserSession[user=" + user.getName() + ", roles=" + Arrays.toString(groups) + "]";
    }
}
