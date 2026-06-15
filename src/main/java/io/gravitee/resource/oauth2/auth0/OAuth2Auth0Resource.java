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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.utils.UUID;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.reactive.api.context.DeploymentContext;
import io.gravitee.node.api.Node;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.node.api.utils.NodeUtils;
import io.gravitee.node.vertx.client.http.VertxHttpClientFactory;
import io.gravitee.plugin.mappers.HttpClientOptionsMapper;
import io.gravitee.plugin.mappers.HttpProxyOptionsMapper;
import io.gravitee.plugin.mappers.SslOptionsMapper;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2ResourceException;
import io.gravitee.resource.oauth2.api.OAuth2ResourceMetadata;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.oauth2.api.openid.UserInfoResponse;
import io.gravitee.resource.oauth2.auth0.configuration.OAuth2Auth0ResourceConfiguration;
import io.gravitee.resource.oauth2.auth0.configuration.OAuth2Auth0ResourceConfigurationEvaluator;
import io.gravitee.resource.oauth2.auth0.contentretriever.vertx.VertxContentRetriever;
import io.gravitee.resource.oauth2.auth0.jwk.JWKSUrlJWKSourceResolver;
import io.reactivex.rxjava3.functions.Consumer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.rxjava3.core.Vertx;
import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.*;
import javax.inject.Inject;
import lombok.AccessLevel;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Gravitee OAuth2 resource for Auth0.
 *
 * <p><strong>Token validation strategy:</strong> Auth0 does not expose an RFC 7662 introspection
 * endpoint for third-party resource servers. Instead, access tokens issued by Auth0 for custom APIs
 * are JWTs whose integrity can be verified locally using the tenant's public signing keys published
 * at the JWKS endpoint. This resource implements that local validation:
 * <ol>
 *   <li>Parse the incoming access token as a signed JWT.</li>
 *   <li>Fetch (and cache) the tenant's JWKS from
 *       {@code https://{domain}/.well-known/jwks.json}.</li>
 *   <li>Verify the JWT signature using the matching public key (RS256 or ES256).</li>
 *   <li>Validate standard claims: {@code exp}, {@code iss}, {@code aud}.</li>
 * </ol>
 *
 * <p><strong>User info:</strong> The {@code userInfo()} method calls the standard OpenID Connect
 * userinfo endpoint ({@code https://{domain}/userinfo}) with the Bearer token to retrieve
 * additional user profile claims.
 *
 * <p><strong>JWKS caching:</strong> Signing keys are cached in memory and refreshed either after
 * the configured TTL or when a token references an unknown key ID (key rotation).
 *
 * @author GraviteeSource Team
 */
public class OAuth2Auth0Resource extends OAuth2Resource<OAuth2Auth0ResourceConfiguration> {

    public static final String ERROR_CHECKING_OAUTH_2_TOKEN = "An error occurs while checking OAuth2 token against Auth0";
    public static final String ERROR_GETTING_USERINFO = "An error occurs while getting userinfo from Auth0";

    static final String AUTH0_SCHEME = "https://";
    private static final String JWKS_PATH = "/.well-known/jwks.json";
    private static final String USERINFO_PATH = "/userinfo";

    private static final String AUTHORIZATION_HEADER_BEARER_SCHEME = "Bearer ";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Logger logger = LoggerFactory.getLogger(OAuth2Auth0Resource.class);

    private HttpClient httpClient;

    private String userAgent;

    /**
     * Computed authorization server base URL: {@code https://{domain}/}
     * Auth0 issues tokens with this as the issuer (trailing slash is mandatory per Auth0 spec).
     */
    private String authorizationServerUrl;

    /** Computed from domain: {@code https://{domain}/userinfo} */
    private String userInfoEndpointURI;

    /** Computed from domain: {@code https://{domain}/.well-known/jwks.json} */
    private String jwksUri;

    @Setter(AccessLevel.PACKAGE)
    private OAuth2Auth0ResourceConfiguration configuration;

    /**
     * Overrides the Auth0 base URL scheme+host prefix. Defaults to {@value AUTH0_SCHEME}.
     * Package-private to allow redirection to a local mock server in tests.
     */
    @Setter(AccessLevel.PACKAGE)
    private String auth0BaseUrl = AUTH0_SCHEME;

    @Inject
    @Setter
    private DeploymentContext deploymentContext;

    private JWKSUrlJWKSourceResolver<SecurityContext> sourceResolver;

    @Override
    public OAuth2Auth0ResourceConfiguration configuration() {
        if (configuration == null) {
            return super.configuration();
        }
        return configuration;
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        configuration = new OAuth2Auth0ResourceConfigurationEvaluator(configuration()).evalNow(deploymentContext);

        String domain = configuration().getDomain();
        // Auth0 issues tokens with issuer = https://{domain}/ (trailing slash required)
        authorizationServerUrl = auth0BaseUrl + domain + "/";
        userInfoEndpointURI = auth0BaseUrl + domain + USERINFO_PATH;
        jwksUri = auth0BaseUrl + domain + JWKS_PATH;

        logger.info(
            "Starting Auth0 OAuth2 resource for domain '{}' (authorization server: {}, JWKS: {})",
            domain,
            authorizationServerUrl,
            jwksUri
        );

        URI targetUri = URI.create(userInfoEndpointURI);
        int port = targetUri.getPort() != -1 ? targetUri.getPort() : ("https".equals(targetUri.getScheme()) ? 443 : 80);
        URL targetUrl = new URL(targetUri.getScheme(), targetUri.getHost(), port, targetUri.toURL().getFile());

        httpClient = VertxHttpClientFactory.builder()
            .vertx(deploymentContext.getComponent(Vertx.class))
            .nodeConfiguration(deploymentContext.getComponent(Configuration.class))
            .defaultTarget(targetUrl.toString())
            .httpOptions(HttpClientOptionsMapper.INSTANCE.map(configuration().getHttpClientOptions()))
            .sslOptions(SslOptionsMapper.INSTANCE.map(configuration().getSslOptions()))
            .proxyOptions(HttpProxyOptionsMapper.INSTANCE.map(configuration().getHttpProxyOptions()))
            .build()
            .createHttpClient()
            .getDelegate();

        userAgent = NodeUtils.userAgent(deploymentContext.getComponent(Node.class));

        sourceResolver = prepareJWKSourceResolver();

        // Pre-load the JWKS at startup so the first request does not incur the fetch latency.
        sourceResolver
            .initialize()
            .doOnError(
                new Consumer<Throwable>() {
                    @Override
                    public void accept(Throwable throwable) throws Throwable {
                        logger.warn(
                            "Failed to pre-load JWKS from {}. Token validation will be attempted at first request: {}",
                            jwksUri,
                            throwable.getMessage()
                        );
                    }
                }
            )
            .blockingAwait();
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();
        try {
            httpClient.close();
        } catch (IllegalStateException ise) {
            logger.warn(ise.getMessage());
        }
    }

    /**
     * Validates the access token locally by verifying its JWT signature and claims against
     * Auth0's published public keys.
     *
     * <p>The JWKS is fetched and cached; it is only re-fetched when the cache TTL expires or when
     * the token references an unknown key ID (indicating key rotation). The JWKS fetch is executed
     * on Vert.x's worker thread pool to avoid blocking the event loop.
     */
    @Override
    public void introspect(String accessToken, Handler<OAuth2Response> responseHandler) {
        final SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(accessToken);
        } catch (ParseException e) {
            logger.debug("Access token is not a valid JWT: {}", e.getMessage());
            responseHandler.handle(new OAuth2Response(false, "{\"active\":false}"));
            return;
        }

        responseHandler.handle(validateJwt(signedJWT));
    }

    @Override
    public void userInfo(String accessToken, Handler<UserInfoResponse> responseHandler) {
        logger.debug("Getting userinfo from Auth0 endpoint: {}", userInfoEndpointURI);

        final RequestOptions reqOptions = new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setAbsoluteURI(userInfoEndpointURI)
            .putHeader(HttpHeaderNames.USER_AGENT, userAgent)
            .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()))
            .putHeader(HttpHeaderNames.AUTHORIZATION, AUTHORIZATION_HEADER_BEARER_SCHEME + accessToken);

        httpClient
            .request(reqOptions)
            .onFailure(event -> {
                logger.error(ERROR_GETTING_USERINFO, event);
                responseHandler.handle(new UserInfoResponse(event));
            })
            .onSuccess(request ->
                request
                    .send()
                    .onFailure(cause -> {
                        logger.error(ERROR_GETTING_USERINFO, cause);
                        responseHandler.handle(new UserInfoResponse(cause));
                    })
                    .onSuccess(response ->
                        response
                            .body()
                            .onFailure(cause -> {
                                logger.error(ERROR_GETTING_USERINFO, cause);
                                responseHandler.handle(new UserInfoResponse(cause));
                            })
                            .onSuccess(buffer -> {
                                logger.debug("Auth0 userinfo endpoint returned status {}", response.statusCode());
                                if (response.statusCode() == HttpStatusCode.OK_200) {
                                    responseHandler.handle(new UserInfoResponse(true, buffer.toString()));
                                } else {
                                    logger.error(
                                        "An error occurs while getting userinfo from Auth0. Request ended with status {}: {}",
                                        response.statusCode(),
                                        buffer
                                    );
                                    responseHandler.handle(new UserInfoResponse(new OAuth2ResourceException(ERROR_GETTING_USERINFO)));
                                }
                            })
                    )
            );
    }

    @Override
    public String getUserClaim() {
        String claim = configuration().getUserClaim();
        if (claim != null && !claim.isEmpty()) {
            return claim;
        }
        return "sub";
    }

    @Override
    public OAuth2ResourceMetadata getProtectedResourceMetadata(String protectedResourceUri, List<String> scopesSupported) {
        return new OAuth2ResourceMetadata(protectedResourceUri, List.of(authorizationServerUrl), scopesSupported);
    }

    // -------------------------------------------------------------------------
    // JWT validation internals
    // -------------------------------------------------------------------------
    private JWKSUrlJWKSourceResolver<SecurityContext> prepareJWKSourceResolver() {
        // Create a source resolver to resolve the Json Web Keystore from an url.
        return new JWKSUrlJWKSourceResolver<>(
            jwksUri,
            new VertxContentRetriever(
                deploymentContext.getComponent(Vertx.class),
                deploymentContext.getComponent(Configuration.class),
                configuration()
            )
        );
    }

    /**
     * Validates a parsed signed JWT. This method runs on a Vert.x worker thread (called from
     * {@code executeBlocking}) so blocking operations (JWKS HTTP fetch) are acceptable.
     */
    private OAuth2Response validateJwt(SignedJWT signedJWT) {
        try {
            // Create a selector with the given jwks source resolver so keys used to verify jwt signatures will be selected from there.
            final JWSKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(
                signedJWT.getHeader().getAlgorithm(),
                sourceResolver
            );

            // Create a jwt processor with the given selector.
            final DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            final DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = buildClaimsVerifier();

            jwtProcessor.setJWSKeySelector(selector);
            jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);

            JWTClaimsSet claims = jwtProcessor.process(signedJWT, null);

            String payload = buildPayload(claims);
            return new OAuth2Response(true, payload);
        } catch (BadJOSEException | JOSEException e) {
            logger.debug("JWT validation failed for domain '{}': {}", configuration().getDomain(), e.getMessage());
            return new OAuth2Response(false, "{\"active\":false}");
        } catch (Exception e) {
            logger.error(ERROR_CHECKING_OAUTH_2_TOKEN, e);
            return new OAuth2Response(e);
        }
    }

    /**
     * Builds a {@link DefaultJWTClaimsVerifier} that enforces the Auth0 issuer, the
     * configured audience, expiration, and not-before constraints.
     *
     * <p>Auth0 issues tokens with {@code iss = https://{domain}/} (trailing slash is significant).
     */
    private DefaultJWTClaimsVerifier<SecurityContext> buildClaimsVerifier() {
        JWTClaimsSet.Builder exactMatchBuilder = new JWTClaimsSet.Builder().issuer(authorizationServerUrl);

        String audience = configuration().getAudience();

        // we must provide a Set structure which allows null value
        HashSet<String> audiences = new HashSet<>();
        audiences.add(audience);
        return new DefaultJWTClaimsVerifier<>(audiences, exactMatchBuilder.build(), Set.of("sub", "iat", "exp"), null);
    }

    /**
     * Builds an RFC 7662-compatible JSON payload from the validated JWT claims.
     * Date claims ({@code exp}, {@code nbf}, {@code iat}) are converted to Unix timestamps
     * (seconds) as required by the RFC.
     */
    private String buildPayload(JWTClaimsSet claims) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("active", true);

        for (Map.Entry<String, Object> entry : claims.getClaims().entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Date) {
                payload.put(entry.getKey(), ((Date) value).getTime() / 1_000L);
            } else {
                payload.put(entry.getKey(), value);
            }
        }

        return MAPPER.writeValueAsString(payload);
    }
}
