package com.security.jwtDemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.security.jwtDemo.filter.JwtRequestFilter;
import com.security.jwtDemo.service.MyUserDetailsService;

@Configuration
@EnableWebSecurity
public class MyWebConfig {

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Autowired
	private JwtRequestFilter jwtRequestFilter;

	/*
	 * @Bean public PasswordEncoder passwordEncoder() { return new
	 * BCryptPasswordEncoder(); }
	 */
	
	 @Bean
	    public PasswordEncoder passwordEncoder() {
	        // Using NoOpPasswordEncoder to indicate no password encoding
	        return NoOpPasswordEncoder.getInstance();
	    }
	 
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests().requestMatchers("/authenticate").permitAll()
		.requestMatchers("/one").hasAnyAuthority("USER","ADMIN")
		.requestMatchers("/two").hasAnyAuthority("ADMIN")
		.anyRequest()
		.authenticated()
		.and()
		.exceptionHandling().accessDeniedPage("/403")
		.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.addFilterAfter(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	/*
	 * @Bean public AuthenticationManager authenticationManager() throws Exception {
	 * return authenticationManagerBuilder().build(); }
	 */

	/*
	 * @Bean public AuthenticationManagerBuilder authenticationManagerBuilder()
	 * throws Exception { AuthenticationManagerBuilder builder = new
	 * AuthenticationManagerBuilder(new PostProcessorAdapter<Object>());
	 * builder.userDetailsService(myUserDetailsService).passwordEncoder(
	 * passwordEncoder()); return builder; }
	 */

	/*
	 * @Autowired public void configureGlobal(AuthenticationManagerBuilder auth)
	 * throws Exception { auth.userDetailsService(myUserDetailsService)
	 * .passwordEncoder(passwordEncoder()); } }
	 */
	/*
	 * @Bean public AuthenticationManager authenticationManagerBean() throws
	 * Exception { return authenticationManager(); }
	 * 
	 * @Bean public AuthenticationManager authenticationManager() throws Exception {
	 * return
	 * authenticationManagerBuilder().userDetailsService(myUserDetailsService)
	 * .passwordEncoder(passwordEncoder()).build(); }
	 */
	
	@Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationManagerBuilder().userDetailsService(myUserDetailsService)
                .passwordEncoder(passwordEncoder()).and().build();
    }
	
	 private AuthenticationManagerBuilder authenticationManagerBuilder() throws Exception {
	        return new AuthenticationManagerBuilder(new PostProcessorAdapter<Object>());
	    }

		/*
		 * private AuthenticationManagerBuilder authenticationManagerBuilder() throws
		 * Exception { return new AuthenticationManagerBuilder(new
		 * PostProcessorAdapter<Object>()); }
		 */

	private static class PostProcessorAdapter<T> implements ObjectPostProcessor<T> {
		@Override
		public <O extends T> O postProcess(O object) {
			return object;
		}
	}
}
