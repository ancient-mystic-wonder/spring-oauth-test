package oauthtest.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

@Controller
public class OauthController {
    @RequestMapping("/oauth")
    public String index() {
        return "index";
    }

    @RequestMapping("/user")
    public @ResponseBody Map<String, String> user(Principal principal) {
        Map<String, String> map = new LinkedHashMap<String, String>();
        map.put("name", principal.getName());
        return map;
    }
}
