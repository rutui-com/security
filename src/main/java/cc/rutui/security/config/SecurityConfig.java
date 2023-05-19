package cc.rutui.security.config;

import cc.rutui.security.security.CustomTokenFilter;
import cc.rutui.security.security.filter.AuthenticationFilter4EmailCode;
import cc.rutui.security.security.filter.AuthenticationFilter4UsernamePassword;
import cc.rutui.security.security.handler.CustomLogoutSuccessHandler;
import cc.rutui.security.security.provider.AuthenticationProvider4EmailCode;
import cc.rutui.security.security.provider.AuthenticationProvider4UsernamePassword;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

/**
 * @author sy.
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String[] IGNORING = {
            // -- Swagger UI v2
            "/v2/api-docs", "/swagger-resources", "/swagger-resources/**", "/configuration/ui", "/configuration/security", "/swagger-ui.html", "/webjars/**",
            // -- Swagger UI v3 (OpenAPI)
            "/v3/api-docs/**", "/swagger-ui/**",
            // -- Static source
            "/resources/**", "/favicon.ico", "/dist/**"};

    @Autowired
    private Cache cache;
    @Autowired
    private CustomTokenFilter customTokenFilter;
    @Autowired
    private CustomLogoutSuccessHandler customLogoutSuccessHandler;
    @Autowired
    private AuthenticationProvider4EmailCode authenticationProvider4EmailCode;
    @Autowired
    private AuthenticationProvider4UsernamePassword authenticationProvider4UsernamePassword;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 关闭csrf
                .csrf().disable()
                // 不通过Session获取SecurityContext
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests()
                // 允许访问
                .antMatchers(IGNORING).permitAll()
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated()
                // 配置登录页
                .and().formLogin().loginPage("/login").permitAll()
                // 配置登出
                .and().logout().logoutSuccessHandler(customLogoutSuccessHandler);

        //把token校验过滤器添加到过滤器链中
        http.addFilterBefore(customTokenFilter, LogoutFilter.class);
        //把登录过滤器添加到过滤器链中,不能采用注入的方式, @Autowired 会导致 AuthenticationManager 为 null
        http.addFilterBefore(new AuthenticationFilter4EmailCode(authenticationManagerBean(), cache), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(new AuthenticationFilter4UsernamePassword(authenticationManagerBean(), cache), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.authenticationProvider(authenticationProvider4EmailCode);
        builder.authenticationProvider(authenticationProvider4UsernamePassword);
    }

}
