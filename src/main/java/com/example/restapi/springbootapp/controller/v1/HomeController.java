package com.example.restapi.springbootapp.controller.v1;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
  
  @GetMapping("/")
  public String welcome( ) { return "SESS-SECURITY"; }
}
