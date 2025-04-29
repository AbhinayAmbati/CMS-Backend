package com.portfolio.cms.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<VerifyJWT> jwtFilter(VerifyJWT verifyJWT) {
        FilterRegistrationBean<VerifyJWT> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(verifyJWT);

        // Specify the routes you want to protect
        registrationBean.addUrlPatterns(
                "/api/admin/getallusers"
        );

        return registrationBean;
    }
}
