/* ==================================================================
 * WebSecurityConfig.java - 27/08/2022 10:06:41 am
 * 
 * Copyright 2022 SolarNetwork.net Dev Team
 * 
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 
 * 02111-1307 USA
 * ==================================================================
 */

package net.solarnetwork.dev.authserver.conf;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.DigestUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import net.solarnetwork.dev.authserver.util.KeyStoreUtils;

/**
 * Web security configuration.
 * 
 * @author matt
 * @version 1.0
 */
@Configuration
public class WebSecurityConfig {

	private static final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);

	@Value("${server.port:9333}")
	private int serverPort = 9333;

	@Value("${app.oauth.client-id:dev-client}")
	private String clientId = "dev-client";

	@Value("${app.oauth.client-secret:dev-client-secret}")
	private String clientSecret = "dev-client-secret";

	@Value("${app.keystore.path:var/keystore}")
	private Path keyStorePath = Paths.get("var/keystore");

	@Value("${app.keystore.password:Secret.123}")
	private String keyStorePassword = "Secret.123";

	@Value("${app.keystore.alias:auth-server}")
	private String keyStoreAlias = "auth-server";

	@ConfigurationProperties(prefix = "app.oauth.scopes")
	@Bean
	@Qualifier("scopes")
	public Set<String> oauthScopes() {
		return new LinkedHashSet<>();
	}

	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.exceptionHandling((exceptions) -> exceptions
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
				// Form login handles the redirect to the login page from the
				// authorization server filter chain
				.formLogin(Customizer.withDefaults());

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository(
			@Qualifier("scopes") Set<String> scopes) {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(clientId).clientSecret(clientSecret)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scopes(s -> s.addAll(scopes))
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.tokenSettings(
						TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build())
				.build();

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		String kid = DigestUtils.md5DigestAsHex(publicKey.getEncoded());
		RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(kid).build();
		JWKSet jwkSet = new JWKSet(rsaKey);

		log.info("Loaded JSON Web Key Set kid %s".formatted(kid));

		return new ImmutableJWKSet<>(jwkSet);
	}

	@Bean
	public KeyPair authServerKeyPair(KeyStore store) {
		try {
			if ( store.containsAlias(keyStoreAlias) ) {
				PrivateKey pk = (PrivateKey) store.getKey(keyStoreAlias, keyStorePassword.toCharArray());
				Certificate[] chain = store.getCertificateChain(keyStoreAlias);
				Certificate cert = chain[0];
				if ( cert instanceof X509Certificate x509 ) {
					log.info("Loaded existing key store %s with self-signed certificate %s"
							.formatted(keyStorePath, x509.getSubjectX500Principal().getName()));
				}
				return new KeyPair(cert.getPublicKey(), pk);
			}

			KeyPair kp = KeyStoreUtils.generateRsaKey();
			Certificate cert = KeyStoreUtils.createSignedCertificate(kp,
					"CN=SolarNetwork Dev Auth Server,OU=Development,O=SolarNetwork");
			store.setKeyEntry(keyStoreAlias, kp.getPrivate(), keyStorePassword.toCharArray(),
					new Certificate[] { cert });
			KeyStoreUtils.saveKeyStore(store, keyStorePassword, keyStorePath);
			log.info("!!! Generated new server key pair and saved to key store %s"
					.formatted(keyStorePath));
			return kp;
		} catch ( Exception e ) {
			throw new IllegalStateException("Error loading key store [%s]".formatted(keyStorePath), e);
		}
	}

	@Bean
	public KeyStore keyStore() {
		return KeyStoreUtils.loadKeyStore(keyStorePath, keyStorePassword);
	}

	@Bean
	public ProviderSettings providerSettings() {
		return ProviderSettings.builder().issuer("http://localhost:%d".formatted(serverPort)).build();
	}
}
