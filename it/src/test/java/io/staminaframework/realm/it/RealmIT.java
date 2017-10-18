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

package io.staminaframework.realm.it;

import io.staminaframework.realm.RealmConstants;
import io.staminaframework.realm.UserSession;
import io.staminaframework.realm.UserSessionAdmin;
import io.staminaframework.realm.spi.PasswordHasher;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.event.Event;
import org.osgi.service.event.EventConstants;
import org.osgi.service.event.EventHandler;
import org.osgi.service.useradmin.*;

import javax.inject.Inject;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.concurrent.atomic.AtomicReference;

import static io.staminaframework.realm.UserCredentials.plainTextPassword;
import static io.staminaframework.starter.it.OsgiHelper.lookupBundle;
import static io.staminaframework.starter.it.OsgiHelper.lookupService;
import static io.staminaframework.starter.it.StaminaOptions.staminaDistribution;
import static org.junit.Assert.*;
import static org.ops4j.pax.exam.CoreOptions.*;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.newConfiguration;

/**
 * Integration tests for bundle <code>io.staminaframework.realm</code>.
 *
 * @author Stamina Framework developers
 */
@RunWith(PaxExam.class)
public class RealmIT {
    @Inject
    private UserAdmin userAdmin;
    @Inject
    private UserSessionAdmin userSessionAdmin;
    @Inject
    private BundleContext bundleContext;

    @BeforeClass
    public static void init() throws IOException {
        final Path path = Paths.get(System.getProperty("stamina.realm.file"));
        Files.copy(RealmIT.class.getResourceAsStream("users.properties"), path, StandardCopyOption.REPLACE_EXISTING);
    }

    @AfterClass
    public static void dispose() throws IOException {
        final Path path = Paths.get(System.getProperty("stamina.realm.file"));
        Files.delete(path);
    }

    @Configuration
    public Option[] config() throws IOException {
        // Pax-Exam is accessing this class 2 times:
        // - first: it loads configuration, by calling config()
        // - then: once the OSGi environment started, a bundle which contains this class will
        //   execute these tests.
        //
        // We need to generate a temporary file for the user realm database.
        // We cannot use legacy solutions to handle this file, since we both need to configure
        // the OSGi environment in config() and access the temporary path later
        // (TemporaryFolder from JUnit or a simple static field cannot help us since Pax-Exam
        // is using this class with 2 different JVM instances).
        // The solution is to setup configuration in config(), and store the temporary file path
        // as a JVM system property; then we use this system property later to initialize
        // our environment (Pax-Exam will set up system properties for all JVM instances).

        final Path realmPath = Files.createTempFile("stamina-realm-", ".properties");
        return options(
                newConfiguration("io.staminaframework.realm")
                        .put("userRealm", realmPath.toFile().getPath())
                        .asOption(),
                systemProperty("stamina.realm.file").value(realmPath.toFile().getPath()),
                staminaDistribution(),
                mavenBundle("io.staminaframework.realm", "io.staminaframework.realm").versionAsInProject()
        );
    }

    @Test
    public void testUserAdmin() {
        assertNotNull(userAdmin);

        final Role userAsRole = userAdmin.getRole("foo");
        assertEquals(Role.USER, userAsRole.getType());
        assertTrue(userAsRole instanceof User);

        final User user = (User) userAsRole;
        assertEquals(1, user.getCredentials().size());
        assertTrue(user.hasCredential(RealmConstants.PASSWORD, "bar"));
        assertEquals(1, user.getProperties().size());
        assertEquals("foo", user.getProperties().get(RealmConstants.UID));

        assertEquals("foo", userAdmin.getUser(RealmConstants.UID, "foo").getName());

        final Authorization auth = userAdmin.getAuthorization(user);
        assertNotNull(auth);
        assertEquals(user.getName(), auth.getName());
        assertEquals(1, auth.getRoles().length);
        assertEquals("adm", auth.getRoles()[0]);
        assertTrue(auth.hasRole("adm"));
        assertFalse(auth.hasRole("unknown"));

        final Role anyOneRole = userAdmin.getRole(Role.USER_ANYONE);
        assertNotNull(anyOneRole);
        assertEquals(Role.USER, anyOneRole.getType());
        assertEquals(Role.USER_ANYONE, anyOneRole.getName());
        assertTrue(((User) anyOneRole).getCredentials().isEmpty());
    }

    @Test
    public void testUserAdminRemoveRole() throws InterruptedException {
        assertNotNull(userAdmin.getRole("foo"));

        final AtomicReference<UserAdminEvent> uaEventRef = new AtomicReference<>();
        final UserAdminListener ual = event -> uaEventRef.set(event);
        bundleContext.registerService(UserAdminListener.class, ual, null);

        final AtomicReference<Event> eaEventRef = new AtomicReference<>();
        final EventHandler eh = event -> eaEventRef.set(event);
        final Dictionary<String, Object> ehProps = new Hashtable<>(1);
        ehProps.put(EventConstants.EVENT_TOPIC, "org/osgi/service/useradmin/UserAdmin/*");
        bundleContext.registerService(EventHandler.class, eh, ehProps);

        userAdmin.removeRole("foo");
        Thread.sleep(1000);

        assertNotNull(uaEventRef.get());
        assertEquals(UserAdminEvent.ROLE_REMOVED, uaEventRef.get().getType());
        assertEquals("foo", uaEventRef.get().getRole().getName());
        assertNull(userAdmin.getRole("foo"));

        final ServiceReference<UserSessionAdmin> userAdminRef = bundleContext.getServiceReference(UserSessionAdmin.class);
        assertNotNull(eaEventRef.get());
        assertSame(uaEventRef.get(), eaEventRef.get().getProperty("event"));
        assertEquals(uaEventRef.get().getRole(), eaEventRef.get().getProperty("role"));
        assertEquals(uaEventRef.get().getRole().getName(), eaEventRef.get().getProperty("role.name"));
        assertEquals(uaEventRef.get().getRole().getType(), eaEventRef.get().getProperty("role.type"));
        assertNotNull(eaEventRef.get().getProperty("service.id"));
        assertArrayEquals((String[]) userAdminRef.getProperty(org.osgi.framework.Constants.OBJECTCLASS),
                (String[]) eaEventRef.get().getProperty("service.objectClass"));
        assertEquals(userAdminRef.getProperty(org.osgi.framework.Constants.SERVICE_PID),
                eaEventRef.get().getProperty("service.pid"));
    }

    @Test
    public void testUserAdminCreateUser() {
        final User user = (User) userAdmin.createRole("john", Role.USER);
        user.getCredentials().put(RealmConstants.PASSWORD, plainTextPassword("changeme"));

        userAdmin.getUser(RealmConstants.UID, "john");
    }

    @Test
    public void testUserAdminCreateUserDuplicateName() {
        assertNotNull(userAdmin.createRole("luke", Role.USER));
        assertNull(userAdmin.createRole("luke", Role.USER));
    }

    @Test
    public void testUserAdminCreateUserAnyone() {
        assertNull(userAdmin.createRole(Role.USER_ANYONE, Role.USER));
    }

    @Test
    public void testUserAdminCreateGroup() {
        final Group group = (Group) userAdmin.createRole("managers", Role.GROUP);
        assertNotNull(group);
        assertEquals("managers", group.getName());
        assertEquals(Role.GROUP, group.getType());
    }

    @Test
    public void testPasswordHasherServiceRanking() {
        final ServiceReference<PasswordHasher> ref = bundleContext.getServiceReference(PasswordHasher.class);
        assertEquals("sha256", ref.getProperty(PasswordHasher.HASH_TYPE));
    }

    @Test
    public void testUserAdminResetPassword() {
        User user = userAdmin.getUser(RealmConstants.UID, "foo");
        assertEquals("bar", user.getCredentials().get(RealmConstants.PASSWORD));
        user.getCredentials().remove(RealmConstants.PASSWORD);

        user = userAdmin.getUser(RealmConstants.UID, "foo");
        assertNull(user.getCredentials().get(RealmConstants.PASSWORD));
    }

    @Test
    public void testUserAdminGetGroup() {
        final Group group = (Group) userAdmin.getRole("adm");
        assertNotNull(group);
        assertNotNull(group.getMembers());
        assertEquals(1, group.getMembers().length);
        assertEquals(Role.USER, group.getMembers()[0].getType());
        assertEquals("foo", group.getMembers()[0].getName());
    }

    @Test
    public void testUserAdminAddMemberToGroup() {
        final User user = (User) userAdmin.createRole("john", Role.USER);
        final Group group = (Group) userAdmin.getRole("adm");
        group.addMember(user);

        final Authorization auth = userAdmin.getAuthorization(user);
        assertTrue(auth.hasRole("adm"));
    }

    @Test
    public void testUserAdminCreateUserWithPassword() {
        User user = (User) userAdmin.createRole("john", Role.USER);
        user.getCredentials().put(RealmConstants.PASSWORD, "changeme");

        final Group group = (Group) userAdmin.getRole("adm");
        group.addMember(user);

        user = userAdmin.getUser(RealmConstants.UID, "john");
        assertNotEquals("changeme", user.getCredentials().get(RealmConstants.PASSWORD));
        assertTrue(((String) user.getCredentials().get(RealmConstants.PASSWORD)).startsWith("sha256:"));

        final UserSession session = userSessionAdmin.authenticate("john", "changeme");
        assertNotNull(session);
    }

    @Test
    public void testUserAdminRemoveSaltWhenRemovingUser() throws InterruptedException {
        final User user = (User) userAdmin.createRole("john", Role.USER);
        user.getCredentials().put(RealmConstants.PASSWORD, plainTextPassword("changeme"));

        final Bundle realmBundle = lookupBundle(bundleContext, "io.staminaframework.realm");
        final File saltFile = realmBundle.getDataFile("salt-sha256-john.dat");
        assertTrue(saltFile.exists());

        assertTrue(userAdmin.removeRole("john"));
        Thread.sleep(500);
        assertFalse(saltFile.exists());
    }

    @Test
    public void testHashPassword() {
        final PasswordHasher hasher = lookupService(bundleContext, PasswordHasher.class);
        final String pwd1 = hasher.hash("john", "randompassword");
        final String pwd2 = hasher.hash("john", "randompassword");
        final String pwd3 = hasher.hash("john", "anotherpassword");
        assertEquals(pwd1, pwd2);
        assertNotEquals(pwd1, pwd3);
    }

    @Test
    public void testUserAdminAddGroupToUser() {
        final User user = (User) userAdmin.createRole("john", Role.USER);
        final Group group = (Group) userAdmin.createRole("managers", Role.GROUP);
        group.addMember(user);

        final Authorization auth = userAdmin.getAuthorization(user);
        assertTrue(auth.hasRole("managers"));
    }

    @Test
    public void testUserAdminRemoveGroupFromUser() {
        final User user = userAdmin.getUser(RealmConstants.UID, "foo");
        Authorization auth = userAdmin.getAuthorization(user);
        assertTrue(auth.hasRole("adm"));

        final Group admGroup = (Group) userAdmin.getRole("adm");
        admGroup.removeMember(user);

        auth = userAdmin.getAuthorization(user);
        assertFalse(auth.hasRole("adm"));
    }

    @Test
    public void testUserAdminCreateGroupWithSameUserName() {
        final Group group = (Group) userAdmin.createRole("foo", Role.GROUP);
        assertNull(group);
    }

    @Test
    public void testUserAdminCreateGroupExistingName() {
        final Group group = (Group) userAdmin.createRole("adm", Role.GROUP);
        assertNull(group);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUserAdminCreateUserWithSpaces() {
        userAdmin.createRole("foo bar", Role.USER);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUserAdminCreateUserInvalidChar() {
        userAdmin.createRole("john,", Role.USER);
    }

    @Test
    public void testUserSessionAdmin() {
        assertNotNull(userSessionAdmin);

        final UserSession session = userSessionAdmin.authenticate("foo", plainTextPassword("bar"));
        assertTrue(session.isValid());
        assertTrue(session.isAuthenticated());
        assertEquals(1, session.getRoles().length);
        assertEquals("adm", session.getRoles()[0]);
        assertTrue(session.hasRole("adm"));
        assertEquals("foo", session.getName());

        session.invalid();
        assertFalse(session.isValid());
        assertTrue(session.isAuthenticated());
    }
}
