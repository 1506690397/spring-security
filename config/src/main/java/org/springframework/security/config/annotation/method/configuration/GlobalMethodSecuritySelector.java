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

package org.springframework.security.config.annotation.method.configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.AutoProxyRegistrar;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

/**
 * Dynamically determines which imports to include using the
 * {@link EnableGlobalMethodSecurity} annotation.
 *
 * @author Rob Winch
 * @since 3.2
 * @deprecated Use {@link MethodSecuritySelector} instead
 */
@Deprecated
final class GlobalMethodSecuritySelector implements ImportSelector {

	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		Class<EnableGlobalMethodSecurity> annoType = EnableGlobalMethodSecurity.class;
		Map<String, Object> annotationAttributes = importingClassMetadata.getAnnotationAttributes(annoType.getName(),
				false);
		AnnotationAttributes attributes = AnnotationAttributes.fromMap(annotationAttributes);
		Assert.notNull(attributes, () -> String.format("@%s is not present on importing class '%s' as expected",
				annoType.getSimpleName(), importingClassMetadata.getClassName()));
		// TODO would be nice if could use BeanClassLoaderAware (does not work)
		Class<?> importingClass = ClassUtils.resolveClassName(importingClassMetadata.getClassName(),
				ClassUtils.getDefaultClassLoader());
		boolean skipMethodSecurityConfiguration = GlobalMethodSecurityConfiguration.class
				.isAssignableFrom(importingClass);
		AdviceMode mode = attributes.getEnum("mode");
		boolean isProxy = AdviceMode.PROXY == mode;
		String autoProxyClassName = isProxy ? AutoProxyRegistrar.class.getName()
				: GlobalMethodSecurityAspectJAutoProxyRegistrar.class.getName();
		boolean jsr250Enabled = attributes.getBoolean("jsr250Enabled");
		List<String> classNames = new ArrayList<>(4);
		if (isProxy) {
			classNames.add(MethodSecurityMetadataSourceAdvisorRegistrar.class.getName()); //MethodSecurityMetadataSourceAdvisorRegistrar如果使用的是Spring自带的aop则配置类会被导入该类主要用来向spring容器中注册一个MethodSecurityMetadataSourceAdvisor对象，这个对象定义了AOP中的pointcut和advice
		}
		classNames.add(autoProxyClassName); //autoProxyClassName注册自动代理创建者 根据不同的代理模式而定
		if (!skipMethodSecurityConfiguration) {
			classNames.add(GlobalMethodSecurityConfiguration.class.getName()); //用来提供MethodSecurityMetadataSource和MethodInterceptor两个关键对象  如果开发者自定义配置类继承自GlobalMethodSecurityConfiguration则这里不会导入这个外部配置类
		}
		if (jsr250Enabled) {
			classNames.add(Jsr250MetadataSourceConfiguration.class.getName());
		}
		return classNames.toArray(new String[0]);
	}

}
