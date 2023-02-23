package com.artsiom.chekh.ssproject.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

import static com.artsiom.chekh.ssproject.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
//    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                /* Cross site request forgery (CSRF). Recommendation is to use CSRF protection for any request
                 * disable because used Postman
                 */
                .csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                    .antMatchers("/api/**").hasRole(STUDENT.name())
                    .anyRequest()
                    .authenticated()
                .and()
                    .formLogin() // may be .httpBasic();
                    .loginPage("/login")
                    .permitAll()
                .defaultSuccessUrl("/courses", true)
                .passwordParameter("password") // optional, to change default values
                .usernameParameter("username") // optional, to change default values
                .and()
                    .rememberMe() // default to 2 weeks (cookie). In DB (username, expiration time, md5 hash)
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) // prolonging the session
                    .key("somethingverysecured")
                    .rememberMeParameter("remember-me") // optional, to change default values
                .and()
                    .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // ! logout must be POST (CSRF protection)
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");

    }

    // used to retrieve the user’s authentication and authorization information.
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
//               .roles(STUDENT.name()) // ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
//              .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
//              .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                tomUser
        );
    }
}

