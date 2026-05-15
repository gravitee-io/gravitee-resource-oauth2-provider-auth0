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

import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.reactive.api.context.DeploymentContext;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.BiFunction;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class TestDeploymentContext implements DeploymentContext {

    private final TemplateEngine templateEngine;
    private final ConcurrentMap<Class<?>, Object> components = new ConcurrentHashMap<>();

    @Override
    public <T> T getComponent(Class<T> componentClass) {
        return (T) components.computeIfPresent(componentClass, (aClass, o) -> o);
    }

    @Override
    public TemplateEngine getTemplateEngine() {
        return this.templateEngine;
    }

    public <T> void addComponent(Class<T> componentClass, T instance) {
        components.putIfAbsent(componentClass, instance);
    }
}
