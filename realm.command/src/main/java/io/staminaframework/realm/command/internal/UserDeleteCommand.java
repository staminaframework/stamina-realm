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
import org.osgi.service.useradmin.User;
import org.osgi.service.useradmin.UserAdmin;
import picocli.CommandLine;

import java.io.PrintStream;

/**
 * {@link Command} for deleting an user.
 *
 * @author Stamina Framework developers
 */
@Component(service = Command.class, property = CommandConstants.COMMAND + "=realm:user-del")
@CommandLine.Command(name = "realm:user-del", description = "Delete an existing user.")
public class UserDeleteCommand implements Command {
    @CommandLine.Parameters(index = "0", paramLabel = "userid", description = "User identifier")
    private String userId;
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

        final User user = userAdmin.getUser(RealmConstants.UID, userId);
        if (user == null) {
            throw new RuntimeException("Unknown user: " + userId);
        }
        context.out().println("Deleting user: " + userId);
        userAdmin.removeRole(userId);
    }
}
