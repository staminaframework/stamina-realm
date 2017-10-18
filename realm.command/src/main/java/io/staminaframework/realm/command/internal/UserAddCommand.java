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

package io.staminaframework.realm.command.internal;

import io.staminaframework.command.Command;
import io.staminaframework.command.CommandConstants;
import io.staminaframework.realm.RealmConstants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.log.LogService;
import org.osgi.service.useradmin.Group;
import org.osgi.service.useradmin.Role;
import org.osgi.service.useradmin.User;
import org.osgi.service.useradmin.UserAdmin;
import picocli.CommandLine;

import java.io.PrintStream;
import java.util.Collections;
import java.util.List;

/**
 * {@link Command} for adding an user.
 *
 * @author Stamina Framework developers
 */
@Component(service = Command.class, property = CommandConstants.COMMAND + "=realm:user-add")
@CommandLine.Command(name = "realm:user-add", description = "Add an user to the configuration.")
public class UserAddCommand implements Command {
    @CommandLine.Parameters(index = "0", paramLabel = "userid", description = "User identifier")
    private String userId;
    @CommandLine.Option(description = "Set users groups", names = {"-g", "--groups"})
    private List<String> groups = Collections.emptyList();
    @CommandLine.Option(names = {"-h", "--help"}, usageHelp = true, description = "Show command usage")
    private boolean showHelp;

    @Reference
    private UserAdmin userAdmin;
    @Reference
    private LogService logService;

    @Override
    public void help(PrintStream out) {
        CommandLine.usage(this, out);
    }

    @Override
    public void execute(Context context) throws Exception {
        try {
            CommandLine.populateCommand(this, context.arguments());
        } catch (CommandLine.ParameterException e) {
            logService.log(LogService.LOG_DEBUG, "Failed to parse command-line arguments", e);
            help(context.out());
            return;
        }

        if (showHelp) {
            help(context.out());
            return;
        }

        // Check groups.
        for (final String groupName : groups) {
            Role role = userAdmin.getRole(groupName);
            if (role != null && role.getType() != Role.GROUP) {
                throw new RuntimeException("Invalid group: " + groupName);
            }
        }

        if (userAdmin.getUser(RealmConstants.UID, userId) != null) {
            throw new RuntimeException("User already exists: " + userId);
        }

        // Read user password.
        final char[] passwd = System.console().readPassword("Enter user password: ");

        context.out().println("Creating user: " + userId);
        final User user = (User) userAdmin.createRole(userId, Role.USER);
        if (user == null) {
            throw new RuntimeException("Cannot create user: " + userId);
        }
        if (passwd != null && passwd.length != 0) {
            user.getCredentials().put(RealmConstants.PASSWORD, new String(passwd));
        }

        // Link user to groups.
        for (final String groupName : groups) {
            final Role role = userAdmin.getRole(groupName);
            final Group group;
            if (role == null) {
                context.out().println("Creating group: " + groupName);
                group = (Group) userAdmin.createRole(groupName, Role.GROUP);
            } else if (role.getType() == Role.GROUP) {
                group = (Group) role;
            } else {
                // This should not happen, since we just made checks about groups.
                continue;
            }
            group.addMember(user);
        }

        context.out().println("User successfully created");
    }
}
