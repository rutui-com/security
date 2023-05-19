package cc.rutui.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LoginPageController {

    @RequestMapping("/login")
    public String login() {
        int num = (int) (Math.random() * 2);
        if (num == 0) {
            return "login_e&c";
        } else {
            return "login_u&p";
        }
    }

}