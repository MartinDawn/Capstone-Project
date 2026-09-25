package com.bk.research.classical.tpp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestTemplateConfig {

    private final RestTemplate restTemplate = new RestTemplate();

    @Bean
    public RestTemplate restTemplate() {
        return restTemplate;
    }

    public RestTemplate getRestTemplate() {
        return restTemplate;
    }
}
