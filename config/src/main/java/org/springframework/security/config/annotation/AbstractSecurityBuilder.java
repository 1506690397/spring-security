/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.config.annotation;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A base {@link SecurityBuilder} that ensures the object being built is only built one
 * time.
 *
 * @param <O> the type of Object that is being built
 * @author Rob Winch
 *
 */ //确保只build一次
public abstract class AbstractSecurityBuilder<O> implements SecurityBuilder<O> {

	private AtomicBoolean building = new AtomicBoolean(); //确保即使是多线程环境下配置类也只构建一次

	private O object;

	@Override
	public final O build() throws Exception {
		if (this.building.compareAndSet(false, true)) { //确保只构建一次
			this.object = doBuild(); //具体构建工作交给doBuild去完成
			return this.object;
		}
		throw new AlreadyBuiltException("This object has already been built");
	}

	/**
	 * Gets the object that was built. If it has not been built yet an Exception is
	 * thrown.
	 * @return the Object that was built
	 */ //用来返回构建的对象
	public final O getObject() {
		if (!this.building.get()) {
			throw new IllegalStateException("This object has not been built");
		}
		return this.object;
	}

	/**
	 * Subclasses should implement this to perform the build.
	 * @return the object that should be returned by {@link #build()}.
	 * @throws Exception if an error occurs
	 */ //具体的构建方法
	protected abstract O doBuild() throws Exception;

}
