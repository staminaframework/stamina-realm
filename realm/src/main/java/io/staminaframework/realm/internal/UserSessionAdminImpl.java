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
import java.util.*;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * {@link UserSessionAdmin} implementation.
 *
 * @author Stamina Framework developers
 */
@Component(service = {UserAdmin.class, UserSessionAdmin.class},
        configurationPid = "io.staminaframework.realm")
public class UserSessionAdminImpl implements UserSessionAdmin, UserAdmin, UserRealmFileMonitor.Listener {
    private static final Pattern NAME_PATTERN = Pattern.compile("([a-z]*[A-Z]*[0-9]*_*-*)+");
    private static final Map<Integer, String> EVENT_TYPES = new HashMap<>(4);

    static {
        EVENT_TYPES.put(UserAdminEvent.ROLE_CHANGED, "ROLE_CHANGED");
        EVENT_TYPES.put(UserAdminEvent.ROLE_CREATED, "ROLE_CREATED");
        EVENT_TYPES.put(UserAdminEvent.ROLE_REMOVED, "ROLE_REMOVED");
        EVENT_TYPES.put(UserSession.ROLE_LOGGED_OUT, "ROLE_LOGGED_OUT");
    }

    private static class HashedPassword {
        public final String password;
        public final String hasher;

        public HashedPassword(final String password, final String hasher) {
            this.password = password;
            this.hasher = hasher;
        }
    }

    /**
     * {@link UserSessionAdmin} component configuration.
     */
    public @interface Config {
        /**
         * Path to user realm definitions file.
         */
        String userRealm();

        /**
         * Set to <code>true</code> to monitor user realm file.
         * When the file is updated, user realm is reloaded.
         */
        boolean monitorUserRealm() default true;

        /**
         * Set preferred password hasher to use.
         */
        String preferredPasswordHasher() default "pbkdf2";
    }

    private Properties userDb;
    private File userRealmFile;
    private ThreadPoolExecutor eventDispatcher;
    private UserRealmFileMonitor userRealmFileMonitor;
    private String preferredPasswordHasher;

    private BundleContext bundleContext;
    private ServiceReference<?> serviceRef;
    @Reference
    private LogService logService;
    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile EventAdmin eventAdmin;

    @Activate
    public void activate(ComponentContext componentContext, BundleContext bundleContext, Config config) throws IOException {
        preferredPasswordHasher = config.preferredPasswordHasher();

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

        userRealmFileMonitor = new UserRealmFileMonitor(userRealmFile.toPath(), this, logService);
        if (config.monitorUserRealm()) {
            userRealmFileMonitor.init();
        }
    }

    @Deactivate
    public void deactivate(Config config) {
        if (userRealmFileMonitor != null) {
            if (config.monitorUserRealm()) {
                userRealmFileMonitor.dispose();
            }
            userRealmFileMonitor = null;
        }
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
        userRealmFile = null;
        bundleContext = null;
        serviceRef = null;
    }

    public synchronized User createUser(String name) {
        if (Role.USER_ANYONE.equals(name)) {
            return null;
        }
        if (userDb.containsKey(name)) {
            return null;
        }
        final User user = new UserImpl(this, name, null);
        userDb.put(name, ",");
        logService.log(LogService.LOG_INFO, "Creating user: " + name);
        userRealmFileMonitor.updateFileWithoutNotifying(() -> {
            try {
                userDb.save();
            } catch (IOException e) {
                logService.log(LogService.LOG_ERROR,
                        "Cannot write to user realm file", e);
            }
        });
        return user;
    }

    public synchronized void updateUser(String userId, Dictionary<String, Object> credentials) {
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
            logService.log(LogService.LOG_INFO, "Hashing password for user: " + userId);
            try {
                final HashedPassword hp = hashUserPassword(userId, newPassword, null);
                newUserDef.append(hp.hasher).append(':').append(hp.password);
            } catch (Exception e) {
                logService.log(LogService.LOG_ERROR, "Failed to hash password for user: " + userId, e);
            }
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
        userRealmFileMonitor.updateFileWithoutNotifying(() -> {
            try {
                userDb.save();
                notifyUserAdminListeners(UserAdminEvent.ROLE_CHANGED, lookupUser(userId));
            } catch (IOException e) {
                logService.log(LogService.LOG_ERROR,
                        "Cannot write to user realm file", e);
            }
        });
    }

    public synchronized void addGroupToUser(String userId, String group) {
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
        userRealmFileMonitor.updateFileWithoutNotifying(() -> {
            try {
                userDb.save();
                notifyUserAdminListeners(UserAdminEvent.ROLE_CHANGED, lookupUser(userId));
            } catch (IOException e) {
                logService.log(LogService.LOG_ERROR,
                        "Cannot write to user realm file", e);
            }
        });
    }

    public synchronized void removeGroupFromUser(String userId, String group) {
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
        userRealmFileMonitor.updateFileWithoutNotifying(() -> {
            try {
                userDb.save();
                notifyUserAdminListeners(UserAdminEvent.ROLE_CHANGED, lookupUser(userId));
            } catch (IOException e) {
                logService.log(LogService.LOG_ERROR,
                        "Cannot write to user realm file", e);
            }
        });
    }

    @Override
    public synchronized UserSession authenticate(String userId, Object... credentials) {
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
                        final String hasherType;
                        final int index = storedPassword.indexOf(':');
                        if (index == -1) {
                            hasherType = "plaintext";
                        } else {
                            hasherType = storedPassword.substring(0, index);
                        }
                        try {
                            final String hashed = hashUserPassword(userId, inputPassword, hasherType).password;
                            final String storedPasswordOnly = storedPassword.substring(index + 1);
                            credentialsOk[i] = hashed.equals(storedPasswordOnly);
                        } catch (Exception e) {
                            logService.log(LogService.LOG_ERROR,
                                    "Failed to hash password for user: " + userId, e);
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

    private HashedPassword hashUserPassword(String user, String inputPassword, String type) throws Exception {
        if (type == null) {
            type = preferredPasswordHasher;
        }
        ServiceReference<PasswordHasher> ref = null;
        try {
            final Collection<ServiceReference<PasswordHasher>> refs =
                    bundleContext.getServiceReferences(PasswordHasher.class,
                            "(" + PasswordHasher.HASH_TYPE + "=" + type + ")");
            if (!refs.isEmpty()) {
                ref = refs.iterator().next();
            }
        } catch (InvalidSyntaxException e) {
            logService.log(LogService.LOG_DEBUG,
                    "Unable to select password hasher: " + type, e);
        }
        if (ref == null) {
            logService.log(LogService.LOG_DEBUG,
                    "Password hasher " + type + " not found: using default one (rank-based)");
            ref = bundleContext.getServiceReference(PasswordHasher.class);
        }
        try {
            final PasswordHasher hasher = bundleContext.getService(ref);
            final String hasherType = (String) ref.getProperty(PasswordHasher.HASH_TYPE);
            if (hasherType == null) {
                throw new RuntimeException("Missing service property "
                        + PasswordHasher.HASH_TYPE + " in PasswordHasher service: " + ref);
            }
            logService.log(LogService.LOG_INFO,
                    "Hashing password for user " + user + " using "
                            + hasherType);
            return new HashedPassword(hasher.hash(user, inputPassword), hasherType);
        } finally {
            bundleContext.ungetService(ref);
        }
    }

    public synchronized UserImpl lookupUser(String userId) {
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

    public synchronized GroupImpl lookupGroup(String groupName) {
        final Set<String> memberNames = new HashSet<>(4);

        for (final String userId : userDb.keySet()) {
            final String userDef = userDb.get(userId);
            final String[] tokens = userDef.split(",");
            if (tokens.length != 0) {
                for (int i = 1; i < tokens.length; ++i) {
                    final String group = tokens[i].trim();
                    if (group.length() != 0 && groupName.equals(group)) {
                        memberNames.add(userId);
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

    public synchronized boolean removeUser(String userId) {
        if (userId == null || Role.USER_ANYONE.equals(userId)) {
            return false;
        }
        final User user = lookupUser(userId);
        final boolean removed = user != null;
        if (removed) {
            logService.log(LogService.LOG_INFO, "Removing user: " + userId);
            userDb.remove(userId);
            userRealmFileMonitor.updateFileWithoutNotifying(() -> {
                try {
                    userDb.save();
                    notifyUserAdminListeners(UserAdminEvent.ROLE_REMOVED, user);
                } catch (IOException e) {
                    logService.log(LogService.LOG_ERROR,
                            "Cannot write to user realm file", e);
                }
            });
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
    public synchronized Role createRole(String name, int type) {
        if (Role.USER != type && Role.GROUP != type) {
            throw new IllegalArgumentException("Unsupported role type: " + type);
        }
        checkRoleName(name);

        if (Role.USER == type) {
            final Role user = createUser(name);
            if (user != null) {
                notifyUserAdminListeners(UserAdminEvent.ROLE_CREATED, user);
            }
            return user;
        }

        if (userDb.containsKey(name)) {
            return null;
        }
        if (lookupGroup(name) != null) {
            return null;
        }

        final Group group = new GroupImpl(this, name, null);
        notifyUserAdminListeners(UserAdminEvent.ROLE_CREATED, group);
        return group;
    }

    @Override
    public synchronized boolean removeRole(String name) {
        checkRoleName(name);
        return removeUser(name);
    }

    @Override
    public synchronized Role getRole(String name) {
        checkRoleName(name);
        final User user = lookupUser(name);
        return user == null ? lookupGroup(name) : user;
    }

    @Override
    public synchronized Role[] getRoles(String filter) throws InvalidSyntaxException {
        if (filter != null) {
            throw new UnsupportedOperationException("Filtering is not supported");
        }

        final List<Role> users = userDb.keySet().stream().map(userId -> lookupUser(userId)).collect(Collectors.toList());
        return users.toArray(new Role[users.size()]);
    }

    @Override
    public synchronized User getUser(String key, String value) {
        if (RealmConstants.UID.equals(key)) {
            return (User) getRole(value);
        }
        return null;
    }

    @Override
    public synchronized Authorization getAuthorization(User user) {
        return authenticate(user.getName());
    }

    private void checkRoleName(String name) {
        final Matcher nameMatcher = NAME_PATTERN.matcher(name);
        if (!nameMatcher.matches() && !name.equals(Role.USER_ANYONE)) {
            throw new IllegalArgumentException("Invalid name: " + name);
        }
    }

    @Override
    public synchronized void userRealmFileUpdated() throws Exception {
        final Map<String, User> usersBeforeUpdate =
                userDb.keySet().stream()
                        .map(userId -> lookupUser(userId))
                        .collect(Collectors.toMap(User::getName, Function.identity()));

        if (userRealmFile.exists()) {
            logService.log(LogService.LOG_INFO, "Reloading user realm");
            userDb.clear();
            userDb.load(userRealmFile);
        } else {
            logService.log(LogService.LOG_WARNING,
                    "User realm file deleted: clearing configuration");
            userDb.clear();
        }

        final Map<String, User> usersAfterUpdate =
                userDb.keySet().stream()
                        .map(userId -> lookupUser(userId))
                        .collect(Collectors.toMap(User::getName, Function.identity()));

        // Notify listeners with new users.
        usersAfterUpdate.entrySet().stream()
                .filter(e -> !usersBeforeUpdate.containsKey(e.getKey()))
                .map(e -> e.getValue())
                .forEach(u -> notifyUserAdminListeners(UserAdminEvent.ROLE_CREATED, u));
        // Notify listeners with removed users.
        usersBeforeUpdate.entrySet().stream()
                .filter(e -> !usersAfterUpdate.containsKey(e.getKey()))
                .map(e -> e.getValue())
                .forEach(u -> notifyUserAdminListeners(UserAdminEvent.ROLE_REMOVED, u));
        // Notify listeners with changed users.
        usersAfterUpdate.entrySet().stream()
                .filter(e -> usersBeforeUpdate.containsKey(e.getKey()))
                .filter(e -> !e.getValue().equals(usersBeforeUpdate.get(e.getKey())))
                .map(e -> e.getValue())
                .forEach(u -> notifyUserAdminListeners(UserAdminEvent.ROLE_CHANGED, u));
    }
}
