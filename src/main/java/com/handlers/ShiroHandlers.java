package com.handlers;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/shrio/")
public class ShiroHandlers {

    @RequestMapping("login")
    public String login(@RequestParam("username") String username, @RequestParam("password") String password) {

        Subject currentUser = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        token.setRememberMe(true);

        currentUser.login(token);


        return "user";
    }
}
