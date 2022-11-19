/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

/**
 * An authentication success strategy which can make use of the
 * {@link org.springframework.security.web.savedrequest.DefaultSavedRequest} which may
 * have been stored in the session by the {@link ExceptionTranslationFilter}. When such a
 * request is intercepted and requires authentication, the request data is stored to
 * record the original destination before the authentication process commenced, and to
 * allow the request to be reconstructed when a redirect to the same URL occurs. This
 * class is responsible for performing the redirect to the original URL if appropriate.
 * <p>
 * Following a successful authentication, it decides on the redirect destination, based on
 * the following scenarios:
 * <ul>
 * <li>If the {@code alwaysUseDefaultTargetUrl} property is set to true, the
 * {@code defaultTargetUrl} will be used for the destination. Any
 * {@code DefaultSavedRequest} stored in the session will be removed.</li>
 * <li>If the {@code targetUrlParameter} has been set on the request, the value will be
 * used as the destination. Any {@code DefaultSavedRequest} will again be removed.</li>
 * <li>If a {@link org.springframework.security.web.savedrequest.SavedRequest} is found in
 * the {@code RequestCache} (as set by the {@link ExceptionTranslationFilter} to record
 * the original destination before the authentication process commenced), a redirect will
 * be performed to the Url of that original destination. The {@code SavedRequest} object
 * will remain cached and be picked up when the redirected request is received (See
 * <a href="
 * {@docRoot}/org/springframework/security/web/savedrequest/SavedRequestAwareWrapper.html">SavedRequestAwareWrapper</a>).
 * </li>
 * <li>If no {@link org.springframework.security.web.savedrequest.SavedRequest} is found,
 * it will delegate to the base class.</li>
 * </ul>
 *
 * @author Luke Taylor
 * @since 3.0 //注：用户可以自定义实现SavedRequestAwareAuthenticationSuccessHandler并且可以在配置时指定targetUrlParameter
 */ //在SimpleUrlAuthenticationSuccessHandler基础上增加了请求缓存功能，可以记录之前请求的地址，进而在登录成功后重定向到一开始访问的地址
public class SavedRequestAwareAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	protected final Log logger = LogFactory.getLog(this.getClass());

	private RequestCache requestCache = new HttpSessionRequestCache();

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws ServletException, IOException {
		SavedRequest savedRequest = this.requestCache.getRequest(request, response); //在requestCache中获取缓存下来的请求
		if (savedRequest == null) { //如果没有则说明用户访问登录页面钱并没有访问其他页面，此时直接调用父类的onAuthenticationSuccess方法进行处理
			super.onAuthenticationSuccess(request, response, authentication);
			return;
		}
		String targetUrlParameter = getTargetUrlParameter(); //希望登录成功后重定向的地址例如：localhost:8080/doLogin?target=/hello表示用户登录成功后希望自动重定向到/hello接口
		if (isAlwaysUseDefaultTargetUrl()
				|| (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
			this.requestCache.removeRequest(request, response); //如果targetUrlParameter存在或者alwaysUseDefaultTargetUrl为true则缓存的请求就没有意义了
			super.onAuthenticationSuccess(request, response, authentication); //调用父类方法进行重定向
			return;
		}
		clearAuthenticationAttributes(request);
		// Use the DefaultSavedRequest URL
		String targetUrl = savedRequest.getRedirectUrl(); //如果上面的条件都不满足则直接从缓存中获取重定向地址进行重定向
		getRedirectStrategy().sendRedirect(request, response, targetUrl);//发送重定向  这里的targetUrl是在访问拒绝后保存的url
	}

	public void setRequestCache(RequestCache requestCache) {
		this.requestCache = requestCache;
	}

}
