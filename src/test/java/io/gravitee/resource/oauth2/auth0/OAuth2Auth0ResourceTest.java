/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.oauth2.auth0;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.Mockito.lenient;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.el.TemplateEngine;
import io.gravitee.el.spel.context.SecuredResolver;
import io.gravitee.node.api.Node;
import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.oauth2.api.OAuth2ResourceMetadata;
import io.gravitee.resource.oauth2.auth0.configuration.OAuth2Auth0ResourceConfiguration;
import io.vertx.rxjava3.core.Vertx;
import java.lang.reflect.Field;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationContext;

/**
 * @author GraviteeSource Team
 */
@WireMockTest
@ExtendWith({ MockitoExtension.class })
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class OAuth2Auth0ResourceTest {

    private static final String DOMAIN = "my-tenant.us.auth0.com";
    private static final String AUDIENCE = "https://my-api.example.com";
    private static final String KEY_ID = "test-key-id-1";

    // RSA key pair shared across all tests (generated once for performance)
    private static RSAKey testSigningKey;
    private static String testJwksJson;
    private static TemplateEngine templateEngine;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private Node node;

    private OAuth2Auth0Resource resource;
    private OAuth2Auth0ResourceConfiguration configuration;
    private int wireMockPort;

    @BeforeAll
    static void initClass() throws Exception {
        SecuredResolver.initialize(null);
        templateEngine = TemplateEngine.templateEngine();

        // Generate a 2048-bit RSA key pair for signing test tokens
        testSigningKey = new RSAKeyGenerator(2048).keyID(KEY_ID).algorithm(JWSAlgorithm.RS256).keyUse(KeyUse.SIGNATURE).generate();

        testJwksJson = new JWKSet(testSigningKey.toPublicJWK()).toString();
    }

    @BeforeEach
    void before(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        wireMockPort = wireMockRuntimeInfo.getHttpPort();

        resource = new OAuth2Auth0Resource();
        resource.setApplicationContext(applicationContext);
        resource.setDeploymentContext(new TestDeploymentContext(templateEngine));

        // Redirect all Auth0 endpoints to the local WireMock server
        resource.setAuth0BaseUrl("http://localhost:" + wireMockPort + "/");

        configuration = new OAuth2Auth0ResourceConfiguration();
        configuration.setDomain(DOMAIN);
        configuration.setAudience(AUDIENCE);

        Field configurationField = AbstractConfigurableResource.class.getDeclaredField("configuration");
        configurationField.setAccessible(true);
        configurationField.set(resource, configuration);

        lenient().when(applicationContext.getBean(Node.class)).thenReturn(node);
        lenient().when(applicationContext.getBean(Vertx.class)).thenReturn(Vertx.vertx());

        // Serve the JWKS at the expected Auth0 discovery path
        stubFor(get(urlEqualTo("/" + DOMAIN + "/.well-known/jwks.json")).willReturn(aResponse().withStatus(200).withBody(testJwksJson)));
    }

    // -------------------------------------------------------------------------
    // introspect() — valid tokens
    // -------------------------------------------------------------------------

    @Test
    void should_validate_a_valid_token() throws Exception {
        resource.doStart();

        String token = buildSignedJwt(standardClaims().build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isTrue();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_include_active_true_and_jwt_claims_in_payload() throws Exception {
        resource.doStart();

        String token = buildSignedJwt(standardClaims().claim("custom_claim", "custom-value").build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getPayload()).contains("\"active\":true");
            assertThat(response.getPayload()).contains("\"custom_claim\":\"custom-value\"");
            assertThat(response.getPayload()).contains("\"iss\":\"http://localhost:" + wireMockPort + "/" + DOMAIN + "/\"");
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    // -------------------------------------------------------------------------
    // introspect() — invalid tokens
    // -------------------------------------------------------------------------

    @Test
    void should_reject_an_expired_token() throws Exception {
        resource.doStart();

        Date past = new Date(System.currentTimeMillis() - 3600_000);
        String token = buildSignedJwt(standardClaims().expirationTime(past).build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_reject_a_token_with_wrong_audience() throws Exception {
        resource.doStart();

        String token = buildSignedJwt(standardClaims().audience("https://some-other-api.example.com").build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_reject_a_token_with_wrong_issuer() throws Exception {
        resource.doStart();

        String token = buildSignedJwt(standardClaims().issuer("https://evil.example.com/").build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_reject_a_token_with_issuer_missing_trailing_slash() throws Exception {
        resource.doStart();

        // Auth0 issuer must have a trailing slash; a token without it must be rejected
        String issuerWithoutSlash = "http://localhost:" + wireMockPort + "/" + DOMAIN;
        String token = buildSignedJwt(standardClaims().issuer(issuerWithoutSlash).build());

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_reject_a_token_signed_with_a_different_key() throws Exception {
        resource.doStart();

        RSAKey otherKey = new RSAKeyGenerator(2048).keyID("other-key-id").keyUse(KeyUse.SIGNATURE).generate();
        String token = buildSignedJwt(standardClaims().build(), otherKey);

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(token, response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_reject_a_string_that_is_not_a_jwt() throws Exception {
        resource.doStart();

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect("not-a-jwt-token", response -> {
            assertThat(response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    // -------------------------------------------------------------------------
    // userInfo()
    // -------------------------------------------------------------------------

    @Test
    void should_get_user_info() throws Exception {
        String userInfoPayload = "{\"sub\": \"auth0|abc123\", \"name\": \"Jane Doe\", \"email\": \"jane@example.com\"}";
        stubFor(get(urlEqualTo("/" + DOMAIN + "/userinfo")).willReturn(aResponse().withStatus(200).withBody(userInfoPayload)));

        resource.doStart();

        AtomicBoolean check = new AtomicBoolean();
        resource.userInfo("any-access-token", userInfoResponse -> {
            assertThat(userInfoResponse.isSuccess()).isTrue();
            assertThat(userInfoResponse.getPayload()).isEqualTo(userInfoPayload);
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_not_get_user_info_when_server_returns_401() throws Exception {
        stubFor(get(urlEqualTo("/" + DOMAIN + "/userinfo")).willReturn(aResponse().withStatus(401)));

        resource.doStart();

        AtomicBoolean check = new AtomicBoolean();
        resource.userInfo("expired-access-token", userInfoResponse -> {
            assertThat(userInfoResponse.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_send_bearer_token_in_user_info_request() throws Exception {
        String accessToken = "xxxx-yyyy-zzzz";
        stubFor(
            get(urlEqualTo("/" + DOMAIN + "/userinfo"))
                .withHeader("Authorization", equalTo("Bearer " + accessToken))
                .willReturn(aResponse().withStatus(200).withBody("{\"sub\": \"auth0|abc123\"}"))
        );

        resource.doStart();

        AtomicBoolean check = new AtomicBoolean();
        resource.userInfo(accessToken, userInfoResponse -> check.set(true));

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);

        verify(getRequestedFor(urlEqualTo("/" + DOMAIN + "/userinfo")).withHeader("Authorization", equalTo("Bearer " + accessToken)));
    }

    // -------------------------------------------------------------------------
    // getUserClaim()
    // -------------------------------------------------------------------------

    @Test
    void should_return_sub_as_default_user_claim() {
        assertThat(resource.getUserClaim()).isEqualTo("sub");
    }

    @Test
    void should_return_configured_user_claim_when_set() {
        configuration.setUserClaim("email");
        assertThat(resource.getUserClaim()).isEqualTo("email");
    }

    // -------------------------------------------------------------------------
    // getProtectedResourceMetadata()
    // -------------------------------------------------------------------------

    @Test
    void should_return_correct_authorization_server_in_metadata() throws Exception {
        resource.doStart();

        OAuth2ResourceMetadata metadata = resource.getProtectedResourceMetadata("https://my-api.example.com", List.of());
        assertAll(
            () -> assertThat(metadata.protectedResourceUri()).isEqualTo("https://my-api.example.com"),
            () -> assertThat(metadata.authorizationServers()).hasSize(1),
            () -> assertThat(metadata.authorizationServers().get(0)).isEqualTo("http://localhost:" + wireMockPort + "/" + DOMAIN + "/"),
            () -> assertThat(metadata.scopesSupported()).isEmpty()
        );
    }

    @Test
    void should_forward_scopes_supported_in_metadata() throws Exception {
        resource.doStart();

        List<String> scopes = List.of("openid", "profile", "email");
        OAuth2ResourceMetadata metadata = resource.getProtectedResourceMetadata("https://my-api.example.com", scopes);
        assertThat(metadata.scopesSupported()).containsExactlyElementsOf(scopes);
    }

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    /**
     * Returns a {@link JWTClaimsSet.Builder} pre-populated with valid claims for the test domain.
     * Auth0 issuer always ends with a trailing slash.
     */
    private JWTClaimsSet.Builder standardClaims() {
        String issuer = "http://localhost:" + wireMockPort + "/" + DOMAIN + "/";
        return new JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(AUDIENCE)
            .subject("auth0|test-subject-sub")
            .issueTime(new Date())
            .notBeforeTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 3_600_000L));
    }

    private String buildSignedJwt(JWTClaimsSet claims) throws Exception {
        return buildSignedJwt(claims, testSigningKey);
    }

    private String buildSignedJwt(JWTClaimsSet claims, RSAKey signingKey) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }
}
