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

import org.osgi.service.useradmin.Group;
import org.osgi.service.useradmin.Role;

import java.util.Dictionary;
import java.util.HashSet;
import java.util.Set;

/**
 * {@link Group} implementation.
 *
 * @author Stamina Framework developers
 */
final class GroupImpl implements Group {
    private final UserSessionAdminImpl usa;
    private final String name;
    private final Set<Role> members = new HashSet<>(4);

    public GroupImpl(final UserSessionAdminImpl usa, final String name, final Set<Role> members) {
        if (name == null) {
            throw new IllegalArgumentException("Group name cannot be null");
        }
        this.usa = usa;
        this.name = name;
        if (members != null) {
            this.members.addAll(members);
        }
    }

    @Override
    public boolean addMember(Role role) {
        if (role.getType() != Role.USER) {
            throw new IllegalArgumentException("Unsupported role as a group member: " + role.getType());
        }
        for (final Role member : members) {
            if (member.getName().equals(role.getName())) {
                return false;
            }
        }
        members.add(role);
        usa.addGroupToUser(role.getName(), name);
        return true;
    }

    @Override
    public boolean addRequiredMember(Role role) {
        throw new UnsupportedOperationException("This method is not implemented");
    }

    @Override
    public boolean removeMember(Role role) {
        final boolean removed = members.remove(role);
        usa.removeGroupFromUser(role.getName(), name);
        return removed;
    }

    @Override
    public Role[] getMembers() {
        return members.toArray(new Role[0]);
    }

    @Override
    public Role[] getRequiredMembers() {
        return null;
    }

    @Override
    public Dictionary getCredentials() {
        return EmptyDictionnary.INSTANCE;
    }

    @Override
    public boolean hasCredential(String key, Object value) {
        return false;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public int getType() {
        return Role.GROUP;
    }

    @Override
    public Dictionary getProperties() {
        return EmptyDictionnary.INSTANCE;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GroupImpl group = (GroupImpl) o;

        if (!name.equals(group.name)) return false;
        return members != null ? members.equals(group.members) : group.members == null;
    }

    @Override
    public int hashCode() {
        int result = name.hashCode();
        result = 31 * result + (members != null ? members.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Group[" + name + "]";
    }
}
