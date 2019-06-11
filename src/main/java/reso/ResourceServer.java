package reso;

import java.util.Date;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@EnableResourceServer
@SpringBootApplication
@RestController
public class ResourceServer extends ResourceServerConfigurerAdapter {

	class JwtTokenServices extends DefaultTokenServices {
		MyJwtConverter converter;

		public JwtTokenServices(MyJwtConverter c) {
			converter = c;
		}

		@Override
		public OAuth2Authentication loadAuthentication(String accessTokenValue)
				throws AuthenticationException, InvalidTokenException {
			final Map<String, Object> map = converter.decode(accessTokenValue);
			final OAuth2AccessToken accessToken = converter.extractAccessToken(accessTokenValue, map);
			if (converter.isRefreshToken(accessToken)) {
				throw new InvalidTokenException("Encoded token is a refresh token");
			}
			if (accessToken == null) {
				throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
			} else if (accessToken.isExpired()) {
				throw new InvalidTokenException("Access token expired: " + accessTokenValue);
			}
			final OAuth2Authentication result = converter.extractAuthentication(map);
			if (result == null) {
				throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
			}
			return result;
		}
	}

	class MyJwtConverter extends JwtAccessTokenConverter {
		@Override
		public Map<String, Object> decode(String token) {
			return super.decode(token);
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(ResourceServer.class, args);
	}

	@Value("${oauth.verify-key:123}")
	String verifyKey;

	@Value("${oauth.resource-id:resource}")
	String resourceId;

	@Bean
	public MyJwtConverter accessTokenConverter() {
		final MyJwtConverter converter = new MyJwtConverter();
		converter.setSigningKey(verifyKey);
		return converter;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		// http.authorizeRequests().antMatchers("/hello")
		// .access("#oauth2.hasScope('read') or (!#oauth2.isOAuth() and
		// hasRole('ROLE_USER'))")
		http.authorizeRequests().anyRequest().authenticated();
		// @formatter:on
	}

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		resources.tokenServices(tokenServices()).resourceId(resourceId);
		// resources.authenticationManager(authenticationManager());
	}

	@RequestMapping("/time")
	public String time() {
		return new Date().toString();
	}

	@Primary
	public JwtTokenServices tokenServices() {
		final JwtTokenServices services = new JwtTokenServices(accessTokenConverter());
		services.setTokenStore(tokenStore());
		return services;
	}

	@Bean
	public TokenStore tokenStore() {
		final MyJwtConverter converter = accessTokenConverter();
		return new JwtTokenStore(converter);
	}
}
