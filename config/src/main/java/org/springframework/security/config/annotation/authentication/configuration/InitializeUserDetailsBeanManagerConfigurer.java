/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.configuration;

import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Lazily initializes the global authentication with a {@link UserDetailsService} if it is
 * not yet configured and there is only a single Bean of that type. Optionally, if a
 * {@link PasswordEncoder} is defined will wire this up too.
 *
 * @author Rob Winch
 * @since 4.1
 */ //初始化全局的UserDetailsService对象
@Order(InitializeUserDetailsBeanManagerConfigurer.DEFAULT_ORDER)
class InitializeUserDetailsBeanManagerConfigurer extends GlobalAuthenticationConfigurerAdapter {

	static final int DEFAULT_ORDER = Ordered.LOWEST_PRECEDENCE - 5000;

	private final ApplicationContext context;

	/**
	 * @param context
	 */
	InitializeUserDetailsBeanManagerConfigurer(ApplicationContext context) {
		this.context = context;
	}

	@Override
	public void init(AuthenticationManagerBuilder auth) throws Exception {
		auth.apply(new InitializeUserDetailsManagerConfigurer());
	}
	//配置全局的UserDetailsService对象
	class InitializeUserDetailsManagerConfigurer extends GlobalAuthenticationConfigurerAdapter {

		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			if (auth.isConfigured()) {
				return;
			}
			UserDetailsService userDetailsService = getBeanOrNull(UserDetailsService.class); //从容器中查找UserDetailsService
			if (userDetailsService == null) {
				return;
			}
			PasswordEncoder passwordEncoder = getBeanOrNull(PasswordEncoder.class); //从spring容器中获取一个Password实例
			UserDetailsPasswordService passwordManager = getBeanOrNull(UserDetailsPasswordService.class);
			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(userDetailsService); //将其设置给全局的AuthenticationManagerBuilder对象
			if (passwordEncoder != null) {
				provider.setPasswordEncoder(passwordEncoder); //设置给provider实例
			}
			if (passwordManager != null) {
				provider.setUserDetailsPasswordService(passwordManager);
			}
			provider.afterPropertiesSet();
			auth.authenticationProvider(provider);
		}

		/**
		 * @return a bean of the requested class if there's just a single registered
		 * component, null otherwise.
		 */
		private <T> T getBeanOrNull(Class<T> type) {
			String[] beanNames = InitializeUserDetailsBeanManagerConfigurer.this.context.getBeanNamesForType(type);
			if (beanNames.length != 1) {
				return null;
			}
			return InitializeUserDetailsBeanManagerConfigurer.this.context.getBean(beanNames[0], type);
		}

	}

}
