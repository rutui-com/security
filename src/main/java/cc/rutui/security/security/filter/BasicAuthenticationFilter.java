package cc.rutui.security.security.filter;

import cc.rutui.security.base.ResponseResult;
import cc.rutui.security.security.CustomLoginUser;
import cc.rutui.security.util.JwtUtils;
import com.alibaba.fastjson.JSON;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.cache.Cache;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public abstract class BasicAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    protected BasicAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    protected BasicAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    protected BasicAuthenticationFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(defaultFilterProcessesUrl, authenticationManager);
    }

    protected BasicAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher, AuthenticationManager authenticationManager) {
        super(requiresAuthenticationRequestMatcher, authenticationManager);
    }

    protected void successfulAuthentication(HttpServletResponse response, Authentication authResult, Cache cache) throws IOException {
        // 生成token
        CustomLoginUser customLoginUser = (CustomLoginUser) authResult.getDetails();
        String username = (String) authResult.getPrincipal();
        String authorities = authResult.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        Map<String, Object> jwtClaims = new HashMap<>();
        jwtClaims.put("username", username);
        jwtClaims.put("authorities", authorities);
        String token = Jwts.builder().setClaims(jwtClaims).setSubject(username).setIssuedAt(new Date()).setExpiration(new Date(new Date().getTime() + JwtUtils.JWT_TTL)).signWith(SignatureAlgorithm.HS512, JwtUtils.JWT_KEY).compact();

        // cache data
        cache.put("login:" + username, JSON.toJSONString(customLoginUser));

        // 把token响应给前端
        HashMap<String, String> map = new HashMap<>();
        map.put("username", username);
        map.put("token", token);

        ResponseResult result = new ResponseResult(200, "登陆成功", map);
        response.setContentType("application/json; charset=UTF-8");
        response.getWriter().write(JSON.toJSONString(result));
    }

    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        ResponseResult result = new ResponseResult(0, failed.getMessage());
        response.setContentType("application/json; charset=UTF-8");
        response.getWriter().write(JSON.toJSONString(result));
    }

}
