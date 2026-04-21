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
package io.gravitee.resource.oauth2.auth0.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.gravitee.plugin.annotation.ConfigurationEvaluator;
import io.gravitee.plugin.configurations.http.HttpClientOptions;
import io.gravitee.plugin.configurations.http.HttpProxyOptions;
import io.gravitee.plugin.configurations.ssl.SslOptions;
import io.gravitee.resource.api.ResourceConfiguration;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Setter;

/**
 * Configuration for the Auth0 OAuth2 resource.
 *
 * <p>Auth0 access tokens for custom APIs are JWTs validated locally using the tenant's public
 * signing keys. The JWKS endpoint is automatically derived from the domain:
 * {@code https://{domain}/.well-known/jwks.json}
 *
 * <p>The issuer is {@code https://{domain}/} and the userinfo endpoint is
 * {@code https://{domain}/userinfo}.
 *
 * @author GraviteeSource Team
 */
@ConfigurationEvaluator
@Data
public class OAuth2Auth0ResourceConfiguration implements ResourceConfiguration {

    /**
     * The Auth0 domain (e.g. {@code my-tenant.us.auth0.com} or a custom domain).
     * Found in the Auth0 dashboard under Applications > APIs > Settings.
     * Supports Expression Language.
     */
    private String domain;

    /**
     * The expected audience ({@code aud} claim) for incoming access tokens.
     * In Auth0, this is the API Identifier configured in the Auth0 dashboard
     * (e.g. {@code https://my-api.example.com}).
     * <p>
     * This field is required to prevent token confusion attacks — without it, any valid
     * Auth0 token from the same tenant could be accepted by your API.
     * Supports Expression Language.
     */
    private String audience;

    /**
     * The claim used to identify the end user in analytics logs.
     * Defaults to {@code sub}, the standard JWT subject claim.
     * Supports EL.
     */
    private String userClaim = "sub";

    @JsonProperty("http")
    private HttpClientOptions httpClientOptions = new HttpClientOptions();

    @JsonProperty("proxy")
    private HttpProxyOptions httpProxyOptions = new HttpProxyOptions();

    @JsonProperty("ssl")
    @Setter(AccessLevel.NONE)
    private SslOptions sslOptions;

    public void setSslOptions(SslOptions sslOptions) {
        if (sslOptions == null) {
            this.sslOptions = SslOptions.builder().hostnameVerifier(false).trustAll(true).build();
            return;
        }
        this.sslOptions = sslOptions;
    }
}
