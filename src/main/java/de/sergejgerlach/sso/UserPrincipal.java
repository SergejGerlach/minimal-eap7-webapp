package de.sergejgerlach.sso;

import java.security.Principal;
import java.util.Objects;

public class UserPrincipal implements Principal {
    private final String name;

    public UserPrincipal(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public String toString() {
        return this.name;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Principal)) {
            return false;
        } else {
            String anotherName = ((Principal) o).getName();
            if (this.name == null) {
                return anotherName == null;
            } else {
                return this.name.equals(anotherName);
            }
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }
}
