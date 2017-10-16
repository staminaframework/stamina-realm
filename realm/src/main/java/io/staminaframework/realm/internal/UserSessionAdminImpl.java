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
import io.staminaframework.realm.UserSession;
import io.staminaframework.realm.UserSessionAdmin;
import io.staminaframework.realm.spi.PasswordHasher;
import org.apache.felix.utils.properties.Properties;
import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.osgi.service.event.Event;
import org.osgi.service.event.EventAdmin;
import org.osgi.service.log.LogService;
import org.osgi.service.useradmin.*;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * {@link UserSessionAdmin} implementation.
 *
 * @author Stamina Framework developers
 */
@Component(service = {UserAdmin.class, UserSessionAdmin.class},
        configurationPid = "io.staminaframework.realm")
public class UserSessionAdminImpl implements UserSessionAdmin, UserAdmin {
    private static final Map<Integer, String> EVENT_TYPES = new HashMap<>(4);

    static {
        EVENT_TYPES.put(UserAdminEvent.ROLE_CHANGED, "ROLE_CHANGED");
        EVENT_TYPES.put(UserAdminEvent.ROLE_CREATED, "ROLE_CREATED");
        EVENT_TYPES.put(UserAdminEvent.ROLE_REMOVED, "ROLE_REMOVED");
        EVENT_TYPES.put(UserSession.ROLE_LOGGED_OUT, "ROLE_LOGGED_OUT");
    }

    /**
     * {@link UserSessionAdmin} component configuration.
     */
    public @interface Config {
        /**
         * Path to user realm definitions file.
         */
        String userRealm();
    }

    private Properties userDb;
    private URL userRealmUrl;
    private ThreadPoolExecutor eventDispatcher;

    private BundleContext bundleContext;
    private ServiceReference<?> serviceRef;
    @Reference
    private LogService logService;
    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile EventAdmin eventAdmin;

    @Activate
    public void activate(ComponentContext componentContext, BundleContext bundleContext, Config config) throws IOException {
        eventDispatcher = new ThreadPoolExecutor(1, 1, 10, TimeUnit.SECONDS,
                new LinkedBlockingDeque<>(), task -> {
            final Thread t = new Thread(task, "UserAdmin Event Dispatcher");
            t.setPriority(Thread.MIN_PRIORITY);
            t.setDaemon(false);
            return t;
        });
        eventDispatcher.allowCoreThreadTimeOut(true);

        this.bundleContext = bundleContext;
        this.serviceRef = componentContext.getServiceReference();
        final File userRealmFile;
        if (config.userRealm() == null || config.userRealm().length() == 0) {
            logService.log(LogService.LOG_WARNING, "No user realm file set: using default");

            if (System.getProperty("stamina.conf") != null) {
                userRealmFile = new File(System.getProperty("stamina.conf"), "users.properties");
            } else {
                final File etcDir = new File("etc");
                if (etcDir.exists()) {
                    userRealmFile = new File(etcDir, "users.properties");
                } else {
                    userRealmFile = new File("users.properties");
                }
            }
        } else {
            userRealmFile = new File(config.userRealm()).getCanonicalFile();
            if (!userRealmFile.exists() || userRealmFile.length() == 0) {
                logService.log(LogService.LOG_WARNING, "User realm file is empty or does not exist: "
                        + userRealmFile);
            }
        }

        logService.log(LogService.LOG_INFO,
                "Loading user realm from file: " + userRealmFile);
        userDb = new Properties(userRealmFile, bundleContext);
    }

    @Deactivate
    public void deactivate() {
        if (eventDispatcher != null) {
            eventDispatcher.shutdown();
            try {
                eventDispatcher.awaitTermination(10, TimeUnit.SECONDS);
            } catch (InterruptedException ignore) {
            }
            eventDispatcher = null;
        }

        // Clear references to help GC.
        userDb = null;
        userRealmUrl = null;
        bundleContext = null;
        serviceRef = null;
    }

    public void reload() throws IOException {
        logService.log(LogService.LOG_INFO, "Reloading user realm");
        userDb.load(userRealmUrl);
    }

    public User createUser(String name) {
        if (Role.USER_ANYONE.equals(name)) {
            return null;
        }
        if (userDb.containsKey(name)) {
            return null;
        }
        final User user = new UserImpl(this, name, null);
        userDb.put(name, ",");
        logService.log(LogService.LOG_INFO, "Creating user: " + name);
        try {
            userDb.save();
        } catch (IOException e) {
            logService.log(LogService.LOG_ERROR,
                    "Cannot write to user realm file", e);
        }
        return user;
    }

    public void updateUser(String userId, Dictionary<String, Object> credentials) {
        final String currentDef = userDb.getProperty(userId);
        if (currentDef == null) {
            // This user was removed before its credentials were updated.
            return;
        }
        final String[] tokens = currentDef.split(",");
        final String newPassword = credentials == null ? null : (String) credentials.get(RealmConstants.PASSWORD);
        final SortedSet<String> groups = new TreeSet<>();
        if (tokens.length != 0) {
            // Get current groups.
            for (int i = 1; i < tokens.length; ++i) {
                final String group = tokens[i].trim();
                if (group.length() != 0) {
                    groups.add(group);
                }
            }
        }

        // Write new user definition.
        final StringBuilder newUserDef = new StringBuilder(32);
        if (newPassword != null) {
            newUserDef.append(newPassword);
        }
        newUserDef.append(",");
        boolean first = true;
        for (final String group : groups) {
            if (!first) {
                newUserDef.append(",");
            }
            newUserDef.append(group);
            first = false;
        }
        if (currentDef.equals(newUserDef.toString())) {
            return;
        }
        userDb.put(userId, newUserDef.toString());
        logService.log(LogService.LOG_INFO, "Updating user: " + userId);
        try {
            userDb.save();
            notifyUserAdminListeners(UserAdminEvent.ROLE_CHANGED, lookupUser(userId));
        } catch (IOException e) {
            logService.log(LogService.LOG_ERROR,
                    "Cannot write to user realm file", e);
        }
    }

    public void addGroupToUser(String userId, String group) {
        if (group == null) {
            return;
        }
        final String userDef = userDb.get(userId);
        if (userDef == null) {
            return;
        }

        final String[] tokens = userDef.split(",");
        String password = null;
        final SortedSet<String> groups = new TreeSet<>();
        if (tokens.length != 0) {
            password = tokens[0].trim();
            if (password.length() == 0) {
                password = null;
            }
            for (int i = 1; i < tokens.length; ++i) {
                final String g = tokens[i].trim();
                if (g.length() != 0) {
                    groups.add(g);
                }
            }
        }

        if (!groups.add(group)) {
            return;
        }
        final StringBuilder newUserDef = new StringBuilder(32);
        if (password != null) {
            newUserDef.append(password);
        }
        newUserDef.append(",");
        boolean first = true;
        for (final String g : groups) {
            if (!first) {
                newUserDef.append(",");
            }
            newUserDef.append(g);
        }
        if (userDef.equals(newUserDef.toString())) {
            return;
        }
        userDb.put(userId, newUserDef.toString());
        logService.log(LogService.LOG_INFO, "Updating user: " + userId);
        try {
            userDb.save();
            notifyUserAdminListeners(UserAdminEvent.ROLE_CHANGED, lookupUser(userId));
        } catch (IOException e) {
            logService.log(LogService.LOG_ERROR,
                    "Cannot write to user realm file", e);
        }
    }

    public void removeGroupFromUser(String userId, String group) {
        if (group == null) {
            return;
        }
        final String userDef = userDb.get(userId);
        if (userDef == null) {
            return;
        }

        final String[] tokens = userDef.split(",");
        String password = null;
        final SortedSet<String> groups = new TreeSet<>();
        if (tokens.length != 0) {
            password = tokens[0].trim();
            if (password.length() == 0) {
                password = null;
            }
            for (int i = 1; i < tokens.length; ++i) {
                final String g = tokens[i].trim();
                if (g.length() != 0) {
                    groups.add(g);
                }
            }
        }

        if (!groups.remove(group)) {
            return;
        }
        final StringBuilder newUserDef = new StringBuilder(32);
        if (password != null) {
            newUserDef.append(password);
        }
        newUserDef.append(",");
        boolean first = true;
        for (final String g : groups) {
            if (!first) {
                newUserDef.append(",");
            }
            newUserDef.append(g);
        }
        if (userDef.equals(newUserDef.toString())) {
            return;
        }
        userDb.put(userId, newUserDef.toString());
        logService.log(LogService.LOG_INFO, "Updating user: " + userId);
        try {
            userDb.save();
            notifyUserAdminListeners(UserAdminEvent.ROLE_CHANGED, lookupUser(userId));
        } catch (IOException e) {
            logService.log(LogService.LOG_ERROR,
                    "Cannot write to user realm file", e);
        }
    }

    @Override
    public UserSession authenticate(String userId, Object... credentials) {
        final UserImpl user = lookupUser(userId);
        if (user == null) {
            logService.log(LogService.LOG_DEBUG, "User not found: " + userId);
            return null;
        }
        if (credentials != null) {
            final boolean[] credentialsOk = new boolean[credentials.length];
            for (int i = 0; i < credentials.length; ++i) {
                final Object credential = credentials[i];
                if (credential instanceof String) {
                    final String storedPassword = (String) user.getCredentials()
                            .get(RealmConstants.PASSWORD);
                    if (storedPassword == null) {
                        // This user has no password: move along.
                        logService.log(LogService.LOG_DEBUG, "No password for user " + userId);
                        credentialsOk[i] = true;
                    } else {
                        final String inputPassword = (String) credential;
                        final int index = storedPassword.indexOf(':');
                        final String storedPasswordType;
                        if (index == -1) {
                            storedPasswordType = "plaintext";
                        } else {
                            // Extract password type.
                            storedPasswordType = storedPassword.substring(0, i);
                        }

                        // Find a hasher for this password type.
                        final Collection<ServiceReference<PasswordHasher>> refs;
                        try {
                            refs = bundleContext.getServiceReferences(PasswordHasher.class,
                                    "(" + PasswordHasher.HASH_TYPE + "=" + storedPasswordType + ")");
                        } catch (InvalidSyntaxException ignore) {
                            break;
                        }
                        for (final ServiceReference<PasswordHasher> ref : refs) {
                            try {
                                logService.log(LogService.LOG_DEBUG,
                                        "Hashing password for user " + userId
                                                + " using hash algorithm: " + storedPasswordType);
                                // Hash input password, and compare results.
                                final PasswordHasher ph = bundleContext.getService(ref);
                                final String hashed = ph.hash(userId, inputPassword);
                                credentialsOk[i] = hashed.equals(inputPassword);
                                break;
                            } catch (Exception e) {
                                logService.log(LogService.LOG_WARNING,
                                        "Failed to hash user password", e);
                            } finally {
                                bundleContext.ungetService(ref);
                            }
                        }
                    }
                }
            }
            for (final boolean credentialOk : credentialsOk) {
                if (!credentialOk) {
                    logService.log(LogService.LOG_WARNING,
                            "Invalid credentials for user: " + userId);
                    return null;
                }
            }
        }

        final String userDef = userDb.getProperty(userId);
        final SortedSet<String> groups = new TreeSet<>();
        final String[] tokens = userDef.split(",");
        if (tokens.length != 0) {
            // Read groups.
            for (int i = 1; i < tokens.length; ++i) {
                final String group = tokens[i].trim();
                if (group.length() != 0) {
                    groups.add(group);
                }
            }
        }
        return new UserSessionImpl(this, user,
                groups.isEmpty() ? null : groups.toArray(new String[groups.size()]),
                credentials != null && credentials.length != 0);
    }

    public UserImpl lookupUser(String userId) {
        if (userId == null || Role.USER_ANYONE.equals(userId)) {
            return new UserImpl(this, Role.USER_ANYONE, null);
        }
        for (final Map.Entry<String, String> e : userDb.entrySet()) {
            final String id = e.getKey();
            if (!id.equals(userId)) {
                continue;
            }
            final String data = e.getValue();
            final String[] tokens = data.split(",");

            // Read user password.
            final Hashtable<String, Object> credentials = new Hashtable<>(1);
            if (tokens.length != 0) {
                final String rawPassword = tokens[0].trim();
                if (rawPassword.length() != 0) {
                    credentials.put(RealmConstants.PASSWORD, rawPassword);
                }
            }
            return new UserImpl(this, userId, credentials);
        }
        return null;
    }

    public GroupImpl lookupGroup(String groupName) {
        final Set<String> memberNames = new HashSet<>(userDb.size());

        for (final String userId : userDb.keySet()) {
            final String userDef = userDb.get(userId);
            final String[] tokens = userDef.split(",");
            if (tokens.length != 0) {
                for (int i = 1; i < tokens.length; ++i) {
                    final String group = tokens[i].trim();
                    if (group.length() != 0 && groupName.equals(group)) {
                        memberNames.add(userDef);
                        break;
                    }
                }
            }
        }
        if (memberNames.isEmpty()) {
            return null;
        }

        final Set<Role> members = memberNames.stream().map(userId -> lookupUser(userId)).collect(Collectors.toSet());
        return new GroupImpl(this, groupName, members);
    }

    public boolean removeUser(String userId) {
        if (userId == null || Role.USER_ANYONE.equals(userId)) {
            return false;
        }
        final User user = lookupUser(userId);
        final boolean removed = user != null;
        if (removed) {
            logService.log(LogService.LOG_INFO, "Removing user: " + userId);
            userDb.remove(userId);
            try {
                userDb.save();
            } catch (IOException e) {
                logService.log(LogService.LOG_ERROR,
                        "Cannot write to user realm file", e);
            }
            notifyUserAdminListeners(UserAdminEvent.ROLE_REMOVED, user);
        }
        return removed;
    }

    public void notifyUserAdminListeners(int eventType, Role role) {
        final Collection<ServiceReference<UserAdminListener>> refs;
        try {
            refs = bundleContext.getServiceReferences(UserAdminListener.class, null);
        } catch (InvalidSyntaxException | IllegalStateException ignore) {
            return;
        }
        final String evtName = EVENT_TYPES.get(eventType);
        final UserAdminEvent evt = new UserAdminEvent(serviceRef, eventType, role);
        if (!refs.isEmpty()) {
            if (eventDispatcher != null) {
                logService.log(LogService.LOG_DEBUG,
                        "Notifying UserAdminListener services: event=" + evtName + ", role=" + role.getName());
                // UserAdmin specification requires to asynchronously notify listeners.
                eventDispatcher.execute(() -> {
                    for (final ServiceReference<UserAdminListener> ref : refs) {
                        try {
                            try {
                                final UserAdminListener listener = bundleContext.getService(ref);
                                listener.roleChanged(evt);
                            } finally {
                                bundleContext.ungetService(ref);
                            }
                        } catch (Exception e) {
                            logService.log(LogService.LOG_WARNING,
                                    "Error while calling UserAdminListener: " + ref, e);
                        }
                    }
                });
            }
        }
        if (eventAdmin != null) {
            // UserAdmin specification requires to use EventAdmin if it's available.
            final String topic = "org/osgi/service/useradmin/UserAdmin/" + evtName;
            final Map<String, Object> props = new HashMap<>();
            props.put("event", evt);
            props.put("role", evt.getRole());
            props.put("role.name", evt.getRole().getName());
            props.put("role.type", evt.getRole().getType());
            props.put("service", serviceRef);
            props.put("service.id", serviceRef.getProperty(org.osgi.framework.Constants.SERVICE_ID));
            props.put("service.objectClass", serviceRef.getProperty(org.osgi.framework.Constants.OBJECTCLASS));
            props.put("service.pid", serviceRef.getProperty(org.osgi.framework.Constants.SERVICE_PID));
            eventAdmin.postEvent(new Event(topic, props));
        }
    }

    @Override
    public Role createRole(String name, int type) {
        if (Role.USER != type && Role.GROUP != type) {
            throw new IllegalArgumentException("Unsupported role type: " + type);
        }
        if (Role.USER == type) {
            final Role user = createUser(name);
            if (user != null) {
                notifyUserAdminListeners(UserAdminEvent.ROLE_CREATED, user);
            }
            return user;
        }

        if (userDb.containsKey(name)) {
            throw new IllegalArgumentException("Cannot create group: an user exists with name " + name);
        }
        final Group group = new GroupImpl(this, name, null);
        notifyUserAdminListeners(UserAdminEvent.ROLE_CREATED, group);
        return group;
    }

    @Override
    public boolean removeRole(String name) {
        return removeUser(name);
    }

    @Override
    public Role getRole(String name) {
        final User user = lookupUser(name);
        return user == null ? lookupGroup(name) : user;
    }

    @Override
    public Role[] getRoles(String filter) throws InvalidSyntaxException {
        if (filter != null) {
            throw new UnsupportedOperationException("Filtering is not supported");
        }

        final List<Role> users = userDb.keySet().stream().map(userId -> lookupUser(userId)).collect(Collectors.toList());
        return users.toArray(new Role[users.size()]);
    }

    @Override
    public User getUser(String key, String value) {
        if (RealmConstants.UID.equals(key)) {
            return (User) getRole(value);
        }
        return null;
    }

    @Override
    public Authorization getAuthorization(User user) {
        return authenticate(user.getName());
    }
}
