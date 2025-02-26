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

package org.springframework.security.access.vote;

import java.util.Collection;

import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * Extended RoleVoter which uses a {@link RoleHierarchy} definition to determine the roles
 * allocated to the current user before voting.
 *
 * @author Luke Taylor
 * @since 2.0.4
 * @deprecated Use
 * {@link org.springframework.security.authorization.AuthorityAuthorizationManager#setRoleHierarchy}
 * instead
 */ //根绝角色进行投票   还可通过RoleHierarchyVoterImpl对象对用户具有的角色进行解析获取用户真正“可触达”的角色
@Deprecated
public class RoleHierarchyVoter extends RoleVoter {

	private RoleHierarchy roleHierarchy = null;

	public RoleHierarchyVoter(RoleHierarchy roleHierarchy) {
		Assert.notNull(roleHierarchy, "RoleHierarchy must not be null");
		this.roleHierarchy = roleHierarchy;
	}

	/**
	 * Calls the <tt>RoleHierarchy</tt> to obtain the complete set of user authorities.
	 */
	@Override
	Collection<? extends GrantedAuthority> extractAuthorities(Authentication authentication) {
		return this.roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
	}

}
