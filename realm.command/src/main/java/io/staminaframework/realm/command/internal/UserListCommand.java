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
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.log.LogService;
import org.osgi.service.useradmin.Role;
import org.osgi.service.useradmin.UserAdmin;
import picocli.CommandLine;

import java.io.PrintStream;
import java.util.Arrays;

/**
 * {@link Command} for listing users.
 *
 * @author Stamina Framework developers
 */
@Component(service = Command.class, property = CommandConstants.COMMAND + "=realm:user-list")
@CommandLine.Command(name = "realm:user-list", description = "List users.")
public class UserListCommand implements Command {
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

        final Role[] roles = userAdmin.getRoles(null);
        if (roles != null) {
            Arrays.asList(roles).stream()
                    .filter(r -> r.getType() == Role.USER)
                    .filter(r -> !Role.USER_ANYONE.equals(r.getName()))
                    .map(r -> r.getName())
                    .sorted()
                    .forEach(context.out()::println);
        }
    }
}
