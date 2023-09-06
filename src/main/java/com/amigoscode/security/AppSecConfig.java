package com.amigoscode.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.amigoscode.security.AppUserPermission.*;
import static com.amigoscode.security.AppUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // to enable @PreAuthorize and @PostAuthorize
public class AppSecConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AppSecConfig(PasswordEncoder passwordEncoder) {
        // inject passwordEncoder bean
        this.passwordEncoder = passwordEncoder;
    }

    // Basic Authentication
    // we can use both antMatchers() and @PreAuthorize() together, but the order of antMatchers() does matter (the first match will be used)
    // (it depends on use cases)
    // In this case, antMatcher() is used for /api/** and @PreAuthorize() is used for /management/api/**
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                .permitAll() // to allow access to these paths without authentication
                /* the order of ant matchers does matter (FIRST MATCH with the request will be used) */
                .antMatchers("/api/**").hasRole(STUDENT.name()) // any request to /api/** must be authenticated and have role STUDENT
                .antMatchers("/api/**").hasRole(ADMIN.name()) // any request to /api/** must be authenticated and have role ADMIN
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) // any DELETE request to /management/api/** must be authenticated and have authority COURSE_WRITE
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) // any POST request to /management/api/** must be authenticated and have authority COURSE_WRITE
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) // any PUT request to /management/api/** must be authenticated and have authority COURSE_WRITE
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name()) // any GET request to /management/api/** must be authenticated and have role ADMIN or ADMINTRAINEE
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    // in-memory user details for authentication
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password")) // bcrypt password encoding
//                .roles(STUDENT.name()) // ROLE_STUDENT (role-based authentication)
                .authorities(STUDENT.getGrantedAuthorities()) // permission-based authentication ( or authority-based authentication)
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123")) // bcrypt password encoding
//                .roles(ADMIN.name()) // ROLE_ADMIN (role-based authentication)
                .authorities(ADMIN.getGrantedAuthorities()) // permission-based authentication ( or authority-based authentication )
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123")) // bcrypt password encoding
//                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE (role-based authentication)
                .authorities(ADMINTRAINEE.getGrantedAuthorities()) // permission-based authentication ( or authority-based authentication )
                .build();

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                tomUser
        );
    }


}
