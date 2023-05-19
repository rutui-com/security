package cc.rutui.security.security.filter;

import cc.rutui.security.security.token.AuthenticationToken4UsernamePassword;
import org.springframework.cache.Cache;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthenticationFilter4UsernamePassword extends BasicAuthenticationFilter {

    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";

    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";

    private final Cache cache;

    public AuthenticationFilter4UsernamePassword(AuthenticationManager authenticationManager, Cache cache) {
        super(new AntPathRequestMatcher("/login_auth", "POST"));
        this.cache = cache;
        this.setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        String username = request.getParameter(SPRING_SECURITY_FORM_USERNAME_KEY) + "";
        String password = request.getParameter(SPRING_SECURITY_FORM_PASSWORD_KEY) + "";
        AuthenticationToken4UsernamePassword authenticationToken = new AuthenticationToken4UsernamePassword(username.trim(), password);
        authenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
        return this.getAuthenticationManager().authenticate(authenticationToken);
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(response, authResult, this.cache);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }

}
