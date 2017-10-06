package oauthtest.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
public class OauthController {
    @RequestMapping("/oauth")
    public String index() {
        return "index";
    }

    @RequestMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }
}
