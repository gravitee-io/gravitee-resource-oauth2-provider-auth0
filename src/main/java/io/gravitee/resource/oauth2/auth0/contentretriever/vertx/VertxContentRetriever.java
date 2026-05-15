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
package io.gravitee.resource.oauth2.auth0.contentretriever.vertx;

import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.node.vertx.client.http.VertxHttpClientFactory;
import io.gravitee.node.vertx.client.http.VertxHttpClientOptions;
import io.gravitee.node.vertx.client.ssl.SslOptions;
import io.gravitee.plugin.mappers.HttpClientOptionsMapper;
import io.gravitee.plugin.mappers.HttpProxyOptionsMapper;
import io.gravitee.plugin.mappers.SslOptionsMapper;
import io.gravitee.resource.oauth2.auth0.configuration.OAuth2Auth0ResourceConfiguration;
import io.gravitee.resource.oauth2.auth0.contentretriever.Content;
import io.gravitee.resource.oauth2.auth0.contentretriever.ContentRetriever;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientRequest;
import java.net.URI;
import java.net.URL;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class VertxContentRetriever implements ContentRetriever {

    private static final int MAX_RESPONSE_SIZE = 5_242_880; // 5MB

    private static final int DEFAULT_CONNECT_TIMEOUT = 2000;
    private static final long DEFAULT_REQUEST_TIMEOUT = 2000L;

    private final Vertx vertx;
    private final Configuration nodeConfiguration;

    private HttpClient httpClient;
    private final OAuth2Auth0ResourceConfiguration configuration;

    public VertxContentRetriever(
        final Vertx vertx,
        final Configuration nodeConfiguration,
        final OAuth2Auth0ResourceConfiguration configuration
    ) {
        this.vertx = vertx;
        this.nodeConfiguration = nodeConfiguration;
        this.configuration = configuration;
    }

    public Single<Content> retrieve(String url) {
        final URL finalURL;

        try {
            finalURL = URI.create(url).toURL();
        } catch (Throwable throwable) {
            return Single.error(throwable);
        }

        HttpClient httpClient = buildHttpClient(finalURL);
        final RequestOptions requestOptions = buildRequestOptions(finalURL);

        return httpClient
            .rxRequest(requestOptions)
            .flatMap(HttpClientRequest::rxSend)
            .flatMap(response -> {
                if (response.statusCode() >= 200 && response.statusCode() <= 299) {
                    return response
                        .rxBody()
                        .map(buffer -> {
                            if (buffer.length() > MAX_RESPONSE_SIZE) {
                                throw new IllegalStateException(
                                    String.format(
                                        "Response size %d bytes exceeds maximum allowed size of %d bytes",
                                        buffer.length(),
                                        MAX_RESPONSE_SIZE
                                    )
                                );
                            }
                            return new Content(buffer.toString(), response.getHeader(HttpHeaders.CONTENT_TYPE));
                        });
                } else {
                    return Single.error(
                        new Exception(String.format("Invalid status code %d received from %s", response.statusCode(), finalURL))
                    );
                }
            });
    }

    private HttpClient buildHttpClient(URL url) {
        if (httpClient == null) {
            httpClient = VertxHttpClientFactory.builder()
                .vertx(vertx)
                .nodeConfiguration(nodeConfiguration)
                .httpOptions(HttpClientOptionsMapper.INSTANCE.map(configuration.getHttpClientOptions()))
                .sslOptions(SslOptionsMapper.INSTANCE.map(configuration.getSslOptions()))
                .proxyOptions(HttpProxyOptionsMapper.INSTANCE.map(configuration.getHttpProxyOptions()))
                .defaultTarget(url.toString())
                .build()
                .createHttpClient();
        }

        return httpClient;
    }

    private RequestOptions buildRequestOptions(URL finalURL) {
        return new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setAbsoluteURI(finalURL)
            .setTimeout(DEFAULT_REQUEST_TIMEOUT)
            .setFollowRedirects(true);
    }
}
