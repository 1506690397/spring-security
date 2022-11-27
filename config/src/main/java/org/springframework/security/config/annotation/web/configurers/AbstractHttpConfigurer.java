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

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * Adds a convenient base class for {@link SecurityConfigurer} instances that operate on
 * {@link HttpSecurity}.
 *
 * @author Rob Winch
 */ //为了给HttpSecurity中使用的配置类添加一个方便的父类  提取出共同的操作
public abstract class AbstractHttpConfigurer<T extends AbstractHttpConfigurer<T, B>, B extends HttpSecurityBuilder<B>>
		extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, B> {

	private SecurityContextHolderStrategy securityContextHolderStrategy;

	/**
	 * Disables the {@link AbstractHttpConfigurer} by removing it. After doing so a fresh
	 * version of the configuration can be applied.
	 * @return the {@link HttpSecurityBuilder} for additional customizations
	 */ //禁用某一配置 本质上就是从构建器的configurers集合中移除某一个配置类
	@SuppressWarnings("unchecked")
	public B disable() {
		getBuilder().removeConfigurer(getClass());
		return getBuilder();
	}
	//给某一个对象添加一个对象后置处理器
	@SuppressWarnings("unchecked")
	public T withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
		addObjectPostProcessor(objectPostProcessor);
		return (T) this;
	}

	protected SecurityContextHolderStrategy getSecurityContextHolderStrategy() {
		if (this.securityContextHolderStrategy != null) {
			return this.securityContextHolderStrategy;
		}
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(SecurityContextHolderStrategy.class);
		if (names.length == 1) {
			this.securityContextHolderStrategy = context.getBean(SecurityContextHolderStrategy.class);
		}
		else {
			this.securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
		}
		return this.securityContextHolderStrategy;
	}

}
