package com.amigoscode.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

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
                // DISABLE -> Suited for other clients (not browser) ex Postman
                .csrf().disable() // to disable csrf token
                // ENABLE -> Suited for browser clients
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // to enable csrf token and don't permit to access it from javascript by client side
//                .and()
                .authorizeRequests()
                    .antMatchers("/", "index", "/css/*", "/js/*")
                    .permitAll() // to allow access to these paths without authentication
                    /* the order of ant matchers does matter (FIRST MATCH with the request will be used) */
                    .antMatchers("/api/**").hasAnyRole(STUDENT.name(), ADMIN.name()) // any request to /api/** must be authenticated and have role STUDENT or ADMIN
//                    .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) // any DELETE request to /management/api/** must be authenticated and have authority COURSE_WRITE
//                    .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) // any POST request to /management/api/** must be authenticated and have authority COURSE_WRITE
//                    .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) // any PUT request to /management/api/** must be authenticated and have authority COURSE_WRITE
//                    .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name()) // any GET request to /management/api/** must be authenticated and have role ADMIN or ADMINTRAINEE
                    .anyRequest()
                    .authenticated()
                .and()
                // Basic Authentication
//                    .httpBasic();
                // Form Based Authentication
                .formLogin()
                    .loginPage("/login").permitAll() // to allow access to /login without authentication
//                    .defaultSuccessUrl("/", false) // redirect to / after login success if the user doesn't have any request before login
                    .defaultSuccessUrl("/courses", true) // always redirect to /courses after login success
                    // keep the same parameters name as in login.html
                    .usernameParameter("username") // to customize username parameter (default is username)
                    .passwordParameter("password") // to customize password parameter (default is password)
                .and()
                .rememberMe() // to enable remember me feature (default 2 weeks)
                    // customize remember-me feature
                    // to set remember-me feature to 21 days
                    .tokenValiditySeconds((int) (TimeUnit.DAYS.toSeconds(21)))
                    // MD5 Hashing from username, expiration time, and secret key
                    .key("somethingverysecured")
                    // keep the same parameters name as in login.html
                    .rememberMeParameter("remember-me") // to customize remember-me parameter (default is remember-me)
                .and()
                .logout()
                    .logoutUrl("/logout") // to customize logout url
                    // if CSRF is enabled, we must use POST method for logout to prevent CSRF attack
                    // if CSRF is disabled, we can use GET method for logout (but it's not recommended)
                    // this line is to use GET method for logout (if CSRF is enabled, delete this line)
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    // clear auth, session, and cookies
                    .clearAuthentication(true) // to clear authentication
                    .invalidateHttpSession(true) // to invalidate http session
                    .deleteCookies("JSESSIONID", "remember-me") // to delete cookies
                    // redirect to /login after logout success
                    .logoutSuccessUrl("/login");
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
