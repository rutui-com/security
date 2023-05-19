package cc.rutui.security.security.handler;

import cc.rutui.security.base.ResponseResult;
import com.alibaba.fastjson.JSON;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handles the navigation on logout
 *
 * @author sy.
 */
@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {
    @Autowired
    private Cache cache;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String username = (String) authentication.getPrincipal();
        cache.evictIfPresent("login:" + username);

        ResponseResult result = new ResponseResult(200, "退出成功");
        response.setContentType("application/json; charset=UTF-8");
        response.getWriter().write(JSON.toJSONString(result));
    }

}
