package de.sergejgerlach.sso;

import java.security.Principal;
import java.security.acl.Group;
import java.util.*;

public class GroupPrincipal extends UserPrincipal implements Group {
    private HashMap<Principal, Principal> members = new HashMap<>(3);

    public GroupPrincipal(String groupName) {
        super(groupName);
    }

    public boolean addMember(Principal user) {
        boolean isMember = this.members.containsKey(user);
        if (!isMember) {
            this.members.put(user, user);
        }
        return !isMember;
    }

    public boolean isMember(Principal member) {
        boolean isMember = this.members.containsKey(member);

        if (!isMember) {
            Collection values = this.members.values();
            Iterator iter = values.iterator();

            while (!isMember && iter.hasNext()) {
                Object next = iter.next();
                if (next instanceof Group) {
                    Group group = (Group) next;
                    isMember = group.isMember(member);
                }
            }
        }

        if (!isMember) {
            for (Principal p : this.members.keySet()) {
                if (member instanceof UserPrincipal) {
                    isMember = p.getName() == null ? member.getName() == null : p.getName().equals(member.getName());
                }
                if (isMember) break;
            }
        }

        return isMember;
    }

    public Enumeration<Principal> members() {
        return Collections.enumeration(this.members.values());
    }

    public boolean removeMember(Principal user) {
        Object prev = this.members.remove(user);
        return prev != null;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(this.getName());
        sb.append("(members:");

        for (Object o : this.members.keySet()) {
            sb.append(o);
            sb.append(',');
        }

        sb.setCharAt(sb.length() - 1, ')');
        return sb.toString();
    }
}
