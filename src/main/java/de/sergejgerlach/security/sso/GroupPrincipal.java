package de.sergejgerlach.security.sso;

import java.security.Principal;
import java.security.acl.Group;
import java.util.*;

public class GroupPrincipal extends UserPrincipal implements Group {
    private HashMap<Principal, Principal> members = new HashMap<>(3);

    public GroupPrincipal(String groupName) {
        super(groupName);
    }

    public boolean addMember(Principal member) {
        boolean isMember = this.members.containsKey(member);
        if (!isMember) {
            this.members.putIfAbsent(member, member) ;
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
            if (member instanceof UserPrincipal) {
                for (Principal m : this.members.keySet()) {
                    isMember = m.getName() == null ? member.getName() == null : m.getName().equals(member.getName());
                    if (isMember) break;
                }
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
            sb.append(o).append(',');
        }
        sb.setCharAt(sb.length() - 1, ')');
        return sb.toString();
    }
}
