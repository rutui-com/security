package cc.rutui.security.controller;

import cc.rutui.security.base.ResponseResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @RequestMapping("/hello")
    public ResponseResult<Object> hello() {
        return new ResponseResult<>(200, "success", "以登录，尽情访问");
    }

}