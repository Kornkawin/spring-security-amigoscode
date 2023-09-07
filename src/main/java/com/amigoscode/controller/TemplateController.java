package com.amigoscode.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping("login")
    public String getLoginView() {
        // get login.html from templates
        return "login";
    }

    @GetMapping("courses")
    public String getCourses() {
        // get courses.html from templates
        return "courses";
    }
}
