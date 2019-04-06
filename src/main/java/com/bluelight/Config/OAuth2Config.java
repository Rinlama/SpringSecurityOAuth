package com.bluelight.Config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import com.bluelight.services.UserService;

@Configuration
@EnableAuthorizationServer
public class OAuth2Config extends AuthorizationServerConfigurerAdapter {

	@Qualifier("userDetailsService")
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Value("${varun.oauth.tokenTimeout:3600}")
	private int expiration;
	
	@Autowired
	private DataSource dataSource;
	
	@Bean
	public TokenStore tokenStore(){
		return new JdbcTokenStore(dataSource);
	}
	

	@Bean
	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.tokenStore(tokenStore());
		endpoints.authenticationManager(authenticationManager);
		endpoints.userDetailsService(userDetailsService);
	}
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		//clients.inMemory().withClient("varun").secret("secret").accessTokenValiditySeconds(this.expiration)
	  // .scopes("read","write").authorizedGrantTypes("password","refresh_token").resourceIds("resource");
		clients.jdbc(dataSource);
	}
	
	
	
	
}
