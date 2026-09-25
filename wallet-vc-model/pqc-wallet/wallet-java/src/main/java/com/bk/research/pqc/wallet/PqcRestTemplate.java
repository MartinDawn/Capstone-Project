package com.bk.research.pqc.wallet;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class PqcRestTemplate {

    private final RestTemplate restTemplate;

    public PqcRestTemplate() {
        this.restTemplate = new RestTemplate();
    }

    public RestTemplate getRestTemplate() {
        return restTemplate;
    }
}

