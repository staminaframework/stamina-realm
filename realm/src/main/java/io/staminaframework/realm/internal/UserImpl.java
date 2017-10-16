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

import io.staminaframework.realm.RealmConstants;
import org.osgi.service.useradmin.Role;
import org.osgi.service.useradmin.User;

import java.util.Arrays;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * {@link User} implementation.
 *
 * @author Stamina Framework developers
 */
final class UserImpl implements User {
    private final Hashtable<String, Object> credentials;
    private final String id;
    private final Dictionary<String, Object> properties;
    private final UserSessionAdminImpl usa;

    public UserImpl(final UserSessionAdminImpl usa, final String id,
                    final Hashtable<String, Object> credentials) {
        if (id == null) {
            throw new IllegalArgumentException("User id cannot be null");
        }
        this.usa = usa;
        this.id = id;

        final AtomicBoolean freeze = new AtomicBoolean(true);
        this.credentials = new Hashtable<String, Object>(2) {
            @Override
            public synchronized Object put(String key, Object value) {
                if (!RealmConstants.PASSWORD.equals(key)) {
                    throw new IllegalArgumentException("Unsupported credential property: " + key);
                }
                if (!(value instanceof String)) {
                    throw new IllegalArgumentException("Password property must be a String: " + value);
                }
                final Object old = super.put(key, value);
                if (!freeze.get() && (old == null || !old.equals(value))) {
                    usa.updateUser(id, this);
                }
                return old;
            }

            @Override
            public synchronized Object remove(Object key) {
                final Object old = super.remove(key);
                if (RealmConstants.PASSWORD.equals(key) && old != null) {
                    usa.updateUser(id, this);
                }
                return old;
            }
        };
        if (credentials != null) {
            this.credentials.putAll(credentials);
        }
        freeze.set(false);

        final Dictionary<String, Object> p = new Hashtable<>(1);
        p.put(RealmConstants.UID, id);
        this.properties = new UnmodifiableDictionary<>(p);
    }

    @Override
    public Dictionary getCredentials() {
        return credentials;
    }

    @Override
    public boolean hasCredential(String key, Object value) {
        final Object credential = credentials.get(key);
        if (credential == null) {
            return false;
        }
        if (credential instanceof String) {
            return credential.equals(value);
        }
        if (credential instanceof byte[] && value instanceof byte[]) {
            return Arrays.equals((byte[]) credential, (byte[]) value);
        }
        return false;
    }

    @Override
    public String getName() {
        return id;
    }

    @Override
    public int getType() {
        return Role.USER;
    }

    @Override
    public Dictionary getProperties() {
        return properties;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        UserImpl user = (UserImpl) o;

        if (!credentials.equals(user.credentials)) return false;
        if (!id.equals(user.id)) return false;
        return properties.equals(user.properties);
    }

    @Override
    public int hashCode() {
        int result = credentials.hashCode();
        result = 31 * result + id.hashCode();
        result = 31 * result + properties.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "User[" + id + "]";
    }
}
