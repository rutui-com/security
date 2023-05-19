package cc.rutui.security.security.provider;

import cc.rutui.security.security.CustomUserDetailsService;
import cc.rutui.security.security.token.AuthenticationToken4EmailCode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationProvider4EmailCode implements AuthenticationProvider {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    protected final Log logger = LogFactory.getLog(this.getClass());

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }
        logger.info("EmailCodeAuthentication authentication request: " + authentication);

        UserDetails user = userDetailsService.loadUserByEmail((String) authentication.getPrincipal());

        if (user == null) {
            throw new InternalAuthenticationServiceException("无法获取用户信息");
        }
        logger.info("EmailCodeAuthentication user: " + user);
        // 认证通过
        AuthenticationToken4EmailCode token = new AuthenticationToken4EmailCode(user.getUsername(), user.getPassword(), user.getAuthorities());
        token.setDetails(user);
        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AuthenticationToken4EmailCode.class.isAssignableFrom(authentication);
    }

}
