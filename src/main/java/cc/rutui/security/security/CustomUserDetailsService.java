package cc.rutui.security.security;

import org.springframework.data.util.Pair;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final Map<String, Pair<String, String[]>> USERS = new HashMap<>();

    static {
        Pair<String, String[]> pair1 = Pair.of("123", new String[]{"authority1", "authority2"});
        Pair<String, String[]> pair2 = Pair.of("123456", new String[]{"authority1", "authority2"});
        USERS.put("123", pair1);
        USERS.put("123@qq.com", pair2);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据用户名查找用户，如LDAP，AD，微信，微博，github等账户平台，便于演示采用静态 USERS
        Pair<String, String[]> user = USERS.get(username);
        if (Objects.isNull(user)) {
            return null;
        }
        //TODO 根据用户查询权限信息 添加到LoginUser中
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (user.getSecond().length > 0) {
            for (String authority : user.getSecond()) {
                authorities.add(new SimpleGrantedAuthority(authority));
            }
        }
        //封装成UserDetails对象返回
        return new CustomLoginUser(username, user.getFirst(), authorities);
    }

    public UserDetails loadUserByEmail(String email) throws UsernameNotFoundException {
        //根据用户名查找用户，如LDAP，AD，微信，微博，github等账户平台，便于演示采用静态 USERS
        Pair<String, String[]> user = USERS.get(email);
        if (Objects.isNull(user)) {
            return null;
        }
        //TODO 根据用户查询权限信息 添加到LoginUser中
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (user.getSecond().length > 0) {
            for (String authority : user.getSecond()) {
                authorities.add(new SimpleGrantedAuthority(authority));
            }
        }
        //封装成UserDetails对象返回
        return new CustomLoginUser(email, user.getFirst(), authorities);
    }

}
