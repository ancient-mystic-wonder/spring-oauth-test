package oauthtest.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

@Controller
public class OauthController {
    @RequestMapping("/oauth")
    public String index() {
        return "index";
    }

    @RequestMapping("/user")
    public @ResponseBody Principal user(Principal principal) {
        return principal;
    }
}
