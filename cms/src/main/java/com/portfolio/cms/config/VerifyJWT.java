package com.portfolio.cms.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class VerifyJWT implements Filter, jakarta.servlet.Filter {

    @Value("${JWT_SECRET_KEY}")
    private String secretKey;

    @Override
    public void init(javax.servlet.FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String authHeader = req.getHeader("Authorization");

        if (authHeader == null || authHeader.isEmpty()) {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            res.setContentType("application/json");
            res.getWriter().write("{\"code\":-2,\"message\":\"Access denied. No token provided.\"}");
            return;
        }

        try {
            String token = authHeader;
            Claims claims = Jwts.parser()
                    .setSigningKey(secretKey.getBytes()) // <-- Important change
                    .parseClaimsJws(token)
                    .getBody();

            request.setAttribute("payload", claims);

            chain.doFilter(request, response);

        } catch (JwtException e) {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            res.setContentType("application/json");
            res.getWriter().write("{\"code\":-2,\"message\":\"Invalid token.\"}");
        }
    }

    @Override
    public void doFilter(jakarta.servlet.ServletRequest servletRequest, jakarta.servlet.ServletResponse servletResponse, jakarta.servlet.FilterChain filterChain) throws IOException, jakarta.servlet.ServletException {

    }

    @Override
    public void destroy() {
        // No resource cleanup required
    }
}
