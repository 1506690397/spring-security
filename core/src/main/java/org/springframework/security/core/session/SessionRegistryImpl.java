/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core.session;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationListener;
import org.springframework.core.log.LogMessage;
import org.springframework.util.Assert;

/**
 * Default implementation of
 * {@link org.springframework.security.core.session.SessionRegistry SessionRegistry} which
 * listens for {@link org.springframework.security.core.session.SessionDestroyedEvent
 * SessionDestroyedEvent}s published in the Spring application context.
 * <p>
 * For this class to function correctly in a web application, it is important that you
 * register an <a href="
 * {@docRoot}/org/springframework/security/web/session/HttpSessionEventPublisher.html">HttpSessionEventPublisher</a>
 * in the <tt>web.xml</tt> file so that this class is notified of sessions that expire.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class SessionRegistryImpl implements SessionRegistry, ApplicationListener<AbstractSessionEvent> {

	protected final Log logger = LogFactory.getLog(SessionRegistryImpl.class);
	//注：需要重写user类的equals和hashcode方法否则会话并发管理会失效
	// <principal:Object,SessionIdSet> //保存用户和sessionId之间的关系 key：用户  value：sessionId的集合
	private final ConcurrentMap<Object, Set<String>> principals;

	// <sessionId:Object,SessionInformation> //保存sessionId和sessionInformation之间的映射关系
	private final Map<String, SessionInformation> sessionIds;

	public SessionRegistryImpl() {
		this.principals = new ConcurrentHashMap<>();
		this.sessionIds = new ConcurrentHashMap<>();
	}

	public SessionRegistryImpl(ConcurrentMap<Object, Set<String>> principals,
			Map<String, SessionInformation> sessionIds) {
		this.principals = principals;
		this.sessionIds = sessionIds;
	}

	@Override //返回所有的登录用户对象
	public List<Object> getAllPrincipals() {
		return new ArrayList<>(this.principals.keySet());
	}

	@Override //返回某个用户对应的所有SessionInformation  principal：用户对象  includeExpiredSessions：是否包含已经过期的session
	public List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {
		Set<String> sessionsUsedByPrincipal = this.principals.get(principal);
		if (sessionsUsedByPrincipal == null) {
			return Collections.emptyList();
		}
		List<SessionInformation> list = new ArrayList<>(sessionsUsedByPrincipal.size());
		for (String sessionId : sessionsUsedByPrincipal) {
			SessionInformation sessionInformation = getSessionInformation(sessionId);
			if (sessionInformation == null) {
				continue;
			}
			if (includeExpiredSessions || !sessionInformation.isExpired()) {
				list.add(sessionInformation);
			}
		}
		return list;
	}

	@Override //根据sessionId从sessionIds集合中获取对应的Sessioninformation
	public SessionInformation getSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		return this.sessionIds.get(sessionId);
	}

	@Override //接收session销毁和改变的事件从而管理HttpSession记录
	public void onApplicationEvent(AbstractSessionEvent event) {
		if (event instanceof SessionDestroyedEvent) {
			SessionDestroyedEvent sessionDestroyedEvent = (SessionDestroyedEvent) event;
			String sessionId = sessionDestroyedEvent.getId();
			removeSessionInformation(sessionId);
		}
		else if (event instanceof SessionIdChangedEvent) {
			SessionIdChangedEvent sessionIdChangedEvent = (SessionIdChangedEvent) event;
			String oldSessionId = sessionIdChangedEvent.getOldSessionId();
			if (this.sessionIds.containsKey(oldSessionId)) {
				Object principal = this.sessionIds.get(oldSessionId).getPrincipal();
				removeSessionInformation(oldSessionId);
				registerNewSession(sessionIdChangedEvent.getNewSessionId(), principal);
			}
		}
	}

	@Override //根据sessionId刷新session最后一次请求的时间
	public void refreshLastRequest(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		SessionInformation info = getSessionInformation(sessionId);
		if (info != null) {
			info.refreshLastRequest();
		}
	}

	@Override //保存会话操作
	public void registerNewSession(String sessionId, Object principal) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		Assert.notNull(principal, "Principal required as per interface contract");
		if (getSessionInformation(sessionId) != null) { //如果sessionId已经存在则先将其移除
			removeSessionInformation(sessionId);
		}
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Registering session %s, for principal %s", sessionId, principal));
		} //往sessionIds中添加一个新的sessionInformation
		this.sessionIds.put(sessionId, new SessionInformation(principal, sessionId, new Date()));
		this.principals.compute(principal, (key, sessionsUsedByPrincipal) -> {
			if (sessionsUsedByPrincipal == null) { //如果principals中不包含sessionsUsedByPrincipal则新建一个集合
				sessionsUsedByPrincipal = new CopyOnWriteArraySet<>();
			}
			sessionsUsedByPrincipal.add(sessionId);//将sessionId加入sessionsUsedByPrincipal中
			this.logger.trace(LogMessage.format("Sessions used by '%s' : %s", principal, sessionsUsedByPrincipal));
			return sessionsUsedByPrincipal;
		});
	}

	@Override //移除sessionInformation
	public void removeSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		SessionInformation info = getSessionInformation(sessionId); //获取sessionInformation信息
		if (info == null) {
			return;
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.debug("Removing session " + sessionId + " from set of registered sessions");
		}
		this.sessionIds.remove(sessionId); //先移除session信息
		this.principals.computeIfPresent(info.getPrincipal(), (key, sessionsUsedByPrincipal) -> {
			this.logger.debug(
					LogMessage.format("Removing session %s from principal's set of registered sessions", sessionId));
			sessionsUsedByPrincipal.remove(sessionId); //移除一个用户中目前会话所对应的sessionId
			if (sessionsUsedByPrincipal.isEmpty()) {
				// No need to keep object in principals Map anymore
				this.logger.debug(LogMessage.format("Removing principal %s from registry", info.getPrincipal()));
				sessionsUsedByPrincipal = null;
			}
			this.logger.trace(
					LogMessage.format("Sessions used by '%s' : %s", info.getPrincipal(), sessionsUsedByPrincipal));
			return sessionsUsedByPrincipal;
		});
	}

}
