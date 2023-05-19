package cc.rutui.security.security;

import cc.rutui.security.security.token.BasicAuthenticationToken;
import cc.rutui.security.util.JwtUtils;
import com.alibaba.fastjson.JSON;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Component
@Slf4j
public class CustomTokenFilter extends OncePerRequestFilter {

    @Autowired
    private Cache cache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //获取token
        String token = request.getHeader("token");
        if (StringUtils.hasText(token)) {
            String username;
            try {
                //解析token
                Claims claims = Jwts.parser().setSigningKey(JwtUtils.JWT_KEY).parseClaimsJws(token).getBody();
                username = claims.getSubject();
            } catch (Exception e) {
                //放行给其他 filter 处理
                log.error("token illegal: {}", token);
                filterChain.doFilter(request, response);
                return;
            }
            // get cache
            Cache.ValueWrapper cacheValue = cache.get("login:" + username);
            if (Objects.isNull(cacheValue)) {
                log.error("token invalid: {}", token);
            } else {
                CustomLoginUser user = JSON.parseObject(String.valueOf(cacheValue.get()), CustomLoginUser.class);
                //存入SecurityContextHolder,便于其他地方使用
                Authentication authentication = new BasicAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }

}