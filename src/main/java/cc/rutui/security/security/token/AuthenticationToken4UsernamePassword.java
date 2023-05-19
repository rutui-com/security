package cc.rutui.security.security.token;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AuthenticationToken4UsernamePassword extends BasicAuthenticationToken {

    public AuthenticationToken4UsernamePassword(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public AuthenticationToken4UsernamePassword(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
