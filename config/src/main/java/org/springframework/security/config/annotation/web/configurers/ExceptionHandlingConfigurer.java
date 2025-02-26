/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.web.configurers;

import java.util.LinkedHashMap;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.RequestMatcherDelegatingAccessDeniedHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Adds exception handling for Spring Security related exceptions to an application. All
 * properties have reasonable defaults, so no additional configuration is required other
 * than applying this
 * {@link org.springframework.security.config.annotation.SecurityConfigurer}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link ExceptionTranslationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>If no explicit {@link RequestCache}, is provided a {@link RequestCache} shared
 * object is used to replay the request after authentication is successful</li>
 * <li>{@link AuthenticationEntryPoint} - see
 * {@link #authenticationEntryPoint(AuthenticationEntryPoint)}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */ //配置异常处理
public final class ExceptionHandlingConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<ExceptionHandlingConfigurer<H>, H> {

	private AuthenticationEntryPoint authenticationEntryPoint;

	private AccessDeniedHandler accessDeniedHandler;
	//key是请求匹配器   value是认证失败处理器
	private LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> defaultEntryPointMappings = new LinkedHashMap<>();

	private LinkedHashMap<RequestMatcher, AccessDeniedHandler> defaultDeniedHandlerMappings = new LinkedHashMap<>();

	/**
	 * Creates a new instance
	 * @see HttpSecurity#exceptionHandling()
	 */
	public ExceptionHandlingConfigurer() {
	}

	/**
	 * Shortcut to specify the {@link AccessDeniedHandler} to be used is a specific error
	 * page
	 * @param accessDeniedUrl the URL to the access denied page (i.e. /errors/401)
	 * @return the {@link ExceptionHandlingConfigurer} for further customization
	 * @see AccessDeniedHandlerImpl
	 * @see #accessDeniedHandler(org.springframework.security.web.access.AccessDeniedHandler)
	 */
	public ExceptionHandlingConfigurer<H> accessDeniedPage(String accessDeniedUrl) {
		AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
		accessDeniedHandler.setErrorPage(accessDeniedUrl);
		return accessDeniedHandler(accessDeniedHandler);
	}

	/**
	 * Specifies the {@link AccessDeniedHandler} to be used
	 * @param accessDeniedHandler the {@link AccessDeniedHandler} to be used
	 * @return the {@link ExceptionHandlingConfigurer} for further customization
	 */
	public ExceptionHandlingConfigurer<H> accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		this.accessDeniedHandler = accessDeniedHandler;
		return this;
	}

	/**
	 * Sets a default {@link AccessDeniedHandler} to be used which prefers being invoked
	 * for the provided {@link RequestMatcher}. If only a single default
	 * {@link AccessDeniedHandler} is specified, it will be what is used for the default
	 * {@link AccessDeniedHandler}. If multiple default {@link AccessDeniedHandler}
	 * instances are configured, then a
	 * {@link RequestMatcherDelegatingAccessDeniedHandler} will be used.
	 * @param deniedHandler the {@link AccessDeniedHandler} to use
	 * @param preferredMatcher the {@link RequestMatcher} for this default
	 * {@link AccessDeniedHandler}
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 * @since 5.1
	 */
	public ExceptionHandlingConfigurer<H> defaultAccessDeniedHandlerFor(AccessDeniedHandler deniedHandler,
			RequestMatcher preferredMatcher) {
		this.defaultDeniedHandlerMappings.put(preferredMatcher, deniedHandler);
		return this;
	}

	/**
	 * Sets the {@link AuthenticationEntryPoint} to be used.
	 *
	 * <p>
	 * If no {@link #authenticationEntryPoint(AuthenticationEntryPoint)} is specified,
	 * then
	 * {@link #defaultAuthenticationEntryPointFor(AuthenticationEntryPoint, RequestMatcher)}
	 * will be used. The first {@link AuthenticationEntryPoint} will be used as the
	 * default if no matches were found.
	 * </p>
	 *
	 * <p>
	 * If that is not provided defaults to {@link Http403ForbiddenEntryPoint}.
	 * </p>
	 * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 */
	public ExceptionHandlingConfigurer<H> authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		return this;
	}

	/**
	 * Sets a default {@link AuthenticationEntryPoint} to be used which prefers being
	 * invoked for the provided {@link RequestMatcher}. If only a single default
	 * {@link AuthenticationEntryPoint} is specified, it will be what is used for the
	 * default {@link AuthenticationEntryPoint}. If multiple default
	 * {@link AuthenticationEntryPoint} instances are configured, then a
	 * {@link DelegatingAuthenticationEntryPoint} will be used.
	 * @param entryPoint the {@link AuthenticationEntryPoint} to use
	 * @param preferredMatcher the {@link RequestMatcher} for this default
	 * {@link AuthenticationEntryPoint}
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 */
	public ExceptionHandlingConfigurer<H> defaultAuthenticationEntryPointFor(AuthenticationEntryPoint entryPoint,
			RequestMatcher preferredMatcher) {
		this.defaultEntryPointMappings.put(preferredMatcher, entryPoint);
		return this;
	}

	/**
	 * Gets any explicitly configured {@link AuthenticationEntryPoint}
	 * @return
	 */
	AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return this.authenticationEntryPoint;
	}

	/**
	 * Gets the {@link AccessDeniedHandler} that is configured.
	 * @return the {@link AccessDeniedHandler}
	 */
	AccessDeniedHandler getAccessDeniedHandler() {
		return this.accessDeniedHandler;
	}

	@Override
	public void configure(H http) {
		AuthenticationEntryPoint entryPoint = getAuthenticationEntryPoint(http); //获取认证失败时的处理器
		ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(entryPoint,
				getRequestCache(http)); //创建ExceptionTranslationFilter过滤器传入entryPoint
		AccessDeniedHandler deniedHandler = getAccessDeniedHandler(http); //获取一个deniedHandler
		exceptionTranslationFilter.setAccessDeniedHandler(deniedHandler); //设置给ExceptionTranslationFilter过滤器
		exceptionTranslationFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		exceptionTranslationFilter = postProcess(exceptionTranslationFilter);
		http.addFilter(exceptionTranslationFilter); //添加到SpringSecurity过滤器链中
	}

	/**
	 * Gets the {@link AccessDeniedHandler} according to the rules specified by
	 * {@link #accessDeniedHandler(AccessDeniedHandler)}
	 * @param http the {@link HttpSecurity} used to look up shared
	 * {@link AccessDeniedHandler}
	 * @return the {@link AccessDeniedHandler} to use
	 */
	AccessDeniedHandler getAccessDeniedHandler(H http) {
		AccessDeniedHandler deniedHandler = this.accessDeniedHandler;
		if (deniedHandler == null) {
			deniedHandler = createDefaultDeniedHandler(http);
		}
		return deniedHandler;
	}

	/**
	 * Gets the {@link AuthenticationEntryPoint} according to the rules specified by
	 * {@link #authenticationEntryPoint(AuthenticationEntryPoint)}
	 * @param http the {@link HttpSecurity} used to look up shared
	 * {@link AuthenticationEntryPoint}
	 * @return the {@link AuthenticationEntryPoint} to use
	 */
	AuthenticationEntryPoint getAuthenticationEntryPoint(H http) {
		AuthenticationEntryPoint entryPoint = this.authenticationEntryPoint; //默认情况下this.authenticationEntryPoint为null
		if (entryPoint == null) {
			entryPoint = createDefaultEntryPoint(http); //获取AuthenticationEntryPoint实例
		}
		return entryPoint;
	}

	private AccessDeniedHandler createDefaultDeniedHandler(H http) {
		if (this.defaultDeniedHandlerMappings.isEmpty()) {
			return new AccessDeniedHandlerImpl();
		}
		if (this.defaultDeniedHandlerMappings.size() == 1) {
			return this.defaultDeniedHandlerMappings.values().iterator().next();
		}
		return new RequestMatcherDelegatingAccessDeniedHandler(this.defaultDeniedHandlerMappings,
				new AccessDeniedHandlerImpl());
	}

	private AuthenticationEntryPoint createDefaultEntryPoint(H http) {
		if (this.defaultEntryPointMappings.isEmpty()) { //如果为空则返回一个Http403ForbiddenEntryPoint类型的处理器
			return new Http403ForbiddenEntryPoint();
		}
		if (this.defaultEntryPointMappings.size() == 1) { //如果只有一项则直接取出来进行返回
			return this.defaultEntryPointMappings.values().iterator().next();
		} //如果有多项则使用DelegatingAuthenticationEntryPoint代理类  在代理类中会遍历defaultEntryPointMappings中的每一项  查看当前是否满足其RequestMatcher  如果满足  则使用对应的认证失败处理器来处理
		DelegatingAuthenticationEntryPoint entryPoint = new DelegatingAuthenticationEntryPoint(
				this.defaultEntryPointMappings);
		entryPoint.setDefaultEntryPoint(this.defaultEntryPointMappings.values().iterator().next());
		return entryPoint;
	}

	/**
	 * Gets the {@link RequestCache} to use. If one is defined using
	 * {@link #requestCache(org.springframework.security.web.savedrequest.RequestCache)},
	 * then it is used. Otherwise, an attempt to find a {@link RequestCache} shared object
	 * is made. If that fails, an {@link HttpSessionRequestCache} is used
	 * @param http the {@link HttpSecurity} to attempt to fined the shared object
	 * @return the {@link RequestCache} to use
	 */
	private RequestCache getRequestCache(H http) {
		RequestCache result = http.getSharedObject(RequestCache.class);
		if (result != null) {
			return result;
		}
		return new HttpSessionRequestCache();
	}

}
