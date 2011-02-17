/**
 * The OWASP CSRFGuard Project, BSD License
 * Eric Sheridan (eric.sheridan@owasp.org), Copyright (c) 2011 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of OWASP nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific
 *       prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.owasp.csrfguard;

import java.io.*;
import java.security.*;
import java.util.*;

import javax.servlet.http.*;

import org.owasp.csrfguard.action.*;
import org.owasp.csrfguard.log.*;
import org.owasp.csrfguard.util.*;

public final class CsrfGuard {

	public final static String SESSION_KEY = "Owasp_CsrfGuard_Session_Key";
	
	public final static String PAGE_TOKENS_KEY = "Owasp_CsrfGuard_Pages_Tokens_Key";
	
	private final static String ACTION_PREFIX = "org.owasp.csrfguard.action.";
	
	private final static String UNPROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.unprotected.";
	
	private ILogger logger = null;
	
	private String tokenName = null;
	
	private int tokenLength = -1;
	
	private boolean rotate = false;
	
	private boolean tokenPerPage = false;
	
	private SecureRandom prng = null;
	
	private String newTokenLandingPage = null;
	
	private boolean ajax = false;
	
	private String sessionKey = null;
	
	private Set<String> unprotectedPages = null;
	
	private List<IAction> actions = null;

	public static CsrfGuard newInstance(InputStream inputStream) throws NoSuchAlgorithmException, InstantiationException, IllegalAccessException, ClassNotFoundException, IOException {
		Properties properties = new Properties();

		properties.load(inputStream);

		return newInstance(properties);
	}

	public static CsrfGuard newInstance(Properties properties) throws NoSuchAlgorithmException, InstantiationException, IllegalAccessException, ClassNotFoundException, IOException {
		CsrfGuard csrfGuard = new CsrfGuard();

		/** load simple properties **/
		csrfGuard.setLogger((ILogger) Class.forName(properties.getProperty("org.owasp.csrfguard.Logger", "org.owasp.csrfguard.log.ConsoleLogger")).newInstance());
		csrfGuard.setTokenName(properties.getProperty("org.owasp.csrfguard.TokenName", "OWASP_CSRFGUARD"));
		csrfGuard.setTokenLength(Integer.parseInt(properties.getProperty("org.owasp.csrfguard.TokenLength", "32")));
		csrfGuard.setRotate(Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.Rotate", "false")));
		csrfGuard.setTokenPerPage(Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.TokenPerPage", "false")));
		csrfGuard.setPrng(SecureRandom.getInstance(properties.getProperty("org.owasp.csrfguard.PRNG", "SHA1PRNG")));
		csrfGuard.setNewTokenLandingPage(properties.getProperty("org.owasp.csrfguard.NewTokenLandingPage"));
		csrfGuard.setSessionKey(properties.getProperty("org.owasp.csrfguard.SessionKey", "OWASP_CSRFGUARD_KEY"));
		csrfGuard.setAjax(Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.Ajax", "false")));

		/** first pass: instantiate actions **/
		Map<String, IAction> actionsMap = new HashMap<String, IAction>();

		for (Object obj : properties.keySet()) {
			String key = (String) obj;

			if (key.startsWith(ACTION_PREFIX)) {
				String directive = key.substring(ACTION_PREFIX.length());
				int index = directive.indexOf('.');

				/** action name/class **/
				if (index < 0) {
					String actionClass = properties.getProperty(key);
					IAction action = (IAction) Class.forName(actionClass).newInstance();

					action.setName(directive);
					actionsMap.put(action.getName(), action);
					csrfGuard.getActions().add(action);
				}
			}
		}

		/** second pass: initialize action parameters **/
		for (Object obj : properties.keySet()) {
			String key = (String) obj;

			if (key.startsWith(ACTION_PREFIX)) {
				String directive = key.substring(ACTION_PREFIX.length());
				int index = directive.indexOf('.');

				/** action name/class **/
				if (index >= 0) {
					String actionName = directive.substring(0, index);
					IAction action = actionsMap.get(actionName);

					if (action == null) {
						throw new IOException(String.format("action class %s has not yet been specified", actionName));
					}

					String parameterName = directive.substring(index + 1);
					String parameterValue = properties.getProperty(key);

					action.setParameter(parameterName, parameterValue);
				}
			}
		}

		/** ensure at least one action was defined **/
		if (csrfGuard.getActions().size() <= 0) {
			throw new IOException("failure to define at least one action");
		}

		/** initialize unprotected pages **/
		for (Object obj : properties.keySet()) {
			String key = (String) obj;

			if (key.startsWith(UNPROTECTED_PAGE_PREFIX)) {
				String directive = key.substring(UNPROTECTED_PAGE_PREFIX.length());
				int index = directive.indexOf('.');

				/** action name/class **/
				if (index < 0) {
					String pageUri = properties.getProperty(key);

					csrfGuard.getUnprotectedPages().add(pageUri);
				}
			}
		}

		return csrfGuard;
	}

	public CsrfGuard() {
		actions = new ArrayList<IAction>();
		unprotectedPages = new HashSet<String>();
	}

	public ILogger getLogger() {
		return logger;
	}

	public void setLogger(ILogger logger) {
		this.logger = logger;
	}

	public String getTokenName() {
		return tokenName;
	}

	public void setTokenName(String tokenName) {
		this.tokenName = tokenName;
	}

	public int getTokenLength() {
		return tokenLength;
	}

	public void setTokenLength(int tokenLength) {
		this.tokenLength = tokenLength;
	}

	public boolean isRotateEnabled() {
		return rotate;
	}

	public void setRotate(boolean rotate) {
		this.rotate = rotate;
	}

	public boolean isTokenPerPageEnabled() {
		return tokenPerPage;
	}

	public void setTokenPerPage(boolean tokenPerPage) {
		this.tokenPerPage = tokenPerPage;
	}

	public SecureRandom getPrng() {
		return prng;
	}

	public void setPrng(SecureRandom prng) {
		this.prng = prng;
	}

	public String getNewTokenLandingPage() {
		return newTokenLandingPage;
	}

	public void setNewTokenLandingPage(String newTokenLandingPage) {
		this.newTokenLandingPage = newTokenLandingPage;
	}

	public boolean isAjaxEnabled() {
		return ajax;
	}

	public void setAjax(boolean ajax) {
		this.ajax = ajax;
	}

	public String getSessionKey() {
		return sessionKey;
	}

	public void setSessionKey(String sessionKey) {
		this.sessionKey = sessionKey;
	}

	public Set<String> getUnprotectedPages() {
		return unprotectedPages;
	}

	public List<IAction> getActions() {
		return actions;
	}

	public String getTokenValue(HttpServletRequest request) {
		return getTokenValue(request, request.getRequestURI());
	}

	public String getTokenValue(HttpServletRequest request, String uri) {
		String tokenValue = null;
		HttpSession session = request.getSession(false);

		if (session != null) {
			if (isTokenPerPageEnabled()) {
				@SuppressWarnings("unchecked")
				Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

				if (pageTokens != null) {
					tokenValue = pageTokens.get(uri);
				}
			}

			if (tokenValue == null) {
				tokenValue = (String) session.getAttribute(getSessionKey());
			}
		}

		return tokenValue;
	}
	
	public boolean isValidRequest(HttpServletRequest request, HttpServletResponse response) {
		boolean valid = isUnprotectedPage(request.getRequestURI());
		HttpSession session = request.getSession(true);
		String tokenFromSession = (String) session.getAttribute(getSessionKey());

		/** sending request to protected resource - verify token **/
		if (tokenFromSession != null && !valid) {
			try {
				if (isAjaxEnabled() && isAjaxRequest(request)) {
					verifyAjaxToken(request);
				} else if (isTokenPerPageEnabled()) {
					verifyPageToken(request);
				} else {
					verifySessionToken(request);
				}
				valid = true;
			} catch (CsrfGuardException csrfe) {
				for (IAction action : getActions()) {
					try {
						action.execute(request, response, csrfe, this);
					} catch (CsrfGuardException exception) {
						getLogger().log(LogLevel.Error, exception);
					}
				}
			}

			/** rotate session and page tokens **/
			if (!isAjaxRequest(request) && isRotateEnabled()) {
				rotateTokens(request);
			}
			/** expected token in session - bad state **/
		} else if (tokenFromSession == null) {
			throw new IllegalStateException("CsrfGuard expects the token to exist in session at this point");
		} else {
			/** unprotected page - nothing to do **/
		}

		/** update session with csrfguard **/
		session.setAttribute(CsrfGuard.SESSION_KEY, this);
		return valid;
	}
	
	public void updateToken(HttpSession session) {
		String tokenValue = (String) session.getAttribute(getSessionKey());

		/** Generate a new token and store it in the session. **/
		if (tokenValue == null) {
			try {
				tokenValue = RandomGenerator.generateRandomId(getPrng(), getTokenLength());
			} catch (Exception e) {
				throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
			}

			session.setAttribute(getSessionKey(), tokenValue);
		}
	}

	public void updateTokens(HttpServletRequest request) {
		/** cannot create sessions if response already committed **/
		HttpSession session = request.getSession(false);

		if (session != null) {
			/** create master token if it does not exist **/
			updateToken(session);
			
			/** create page specific token **/
			if (isTokenPerPageEnabled()) {
				@SuppressWarnings("unchecked")
				Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

				/** first time initialization **/
				if (pageTokens == null) {
					pageTokens = new HashMap<String, String>();
					session.setAttribute(CsrfGuard.PAGE_TOKENS_KEY, pageTokens);
				}

				/** create token if it does not exist **/
				if (!isUnprotectedPage(request.getRequestURI()) && !pageTokens.containsKey(request.getRequestURI())) {
					try {
						pageTokens.put(request.getRequestURI(), RandomGenerator.generateRandomId(getPrng(), getTokenLength()));
					} catch (Exception e) {
						throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
					}
				}
			}
		}
	}
	
	public void writeLandingPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String landingPage = getNewTokenLandingPage();

		/** default to current page **/
		if (landingPage == null) {
			StringBuilder sb = new StringBuilder();
			
			sb.append(request.getContextPath());
			sb.append(request.getServletPath());
			
			landingPage = sb.toString();
		}

		/** create auto posting form **/
		StringBuilder sb = new StringBuilder();

		sb.append("<html>\r\n");
		sb.append("<head>\r\n");
		sb.append("<title>OWASP CSRFGuard Project - New Token Landing Page</title>\r\n");
		sb.append("</head>\r\n");
		sb.append("<body>\r\n");
		sb.append("<script type=\"text/javascript\">\r\n");
		sb.append("var form = document.createElement(\"form\");\r\n");
		sb.append("form.setAttribute(\"method\", \"post\");\r\n");
		sb.append("form.setAttribute(\"action\", \"");
		sb.append(landingPage);
		sb.append("\");\r\n");

		/** only include token if needed **/
		if (!isUnprotectedPage(landingPage)) {
			sb.append("var hiddenField = document.createElement(\"input\");\r\n");
			sb.append("hiddenField.setAttribute(\"type\", \"hidden\");\r\n");
			sb.append("hiddenField.setAttribute(\"name\", \"");
			sb.append(getTokenName());
			sb.append("\");\r\n");
			sb.append("hiddenField.setAttribute(\"value\", \"");
			sb.append(getTokenValue(request, landingPage));
			sb.append("\");\r\n");
			sb.append("form.appendChild(hiddenField);\r\n");
		}

		sb.append("document.body.appendChild(form);\r\n");
		sb.append("form.submit();\r\n");
		sb.append("</script>\r\n");
		sb.append("</body>\r\n");
		sb.append("</html>\r\n");

		String code = sb.toString();

		/** setup headers **/
		response.setContentType("text/html");
		response.setContentLength(code.length());

		/** write auto posting form **/
		OutputStream output = null;
		PrintWriter writer = null;

		try {
			output = response.getOutputStream();
			writer = new PrintWriter(output);

			writer.write(code);
			writer.flush();
		} finally {
			Writers.close(writer);
			Streams.close(output);
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		sb.append("\r\n*****************************************************\r\n");
		sb.append("* Owasp.CsrfGuard Properties\r\n");
		sb.append("*\r\n");
		sb.append(String.format("* Logger: %s\r\n", getLogger().getClass().getName()));
		sb.append(String.format("* NewTokenLandingPage: %s\r\n", getNewTokenLandingPage()));
		sb.append(String.format("* PRNG: %s\r\n", getPrng().getAlgorithm()));
		sb.append(String.format("* SessionKey: %s\r\n", getSessionKey()));
		sb.append(String.format("* TokenLength: %s\r\n", getTokenLength()));
		sb.append(String.format("* TokenName: %s\r\n", getTokenName()));
		sb.append(String.format("* Ajax: %s\r\n", isAjaxEnabled()));
		sb.append(String.format("* Rotate: %s\r\n", isRotateEnabled()));
		sb.append(String.format("* TokenPerPage: %s\r\n", isTokenPerPageEnabled()));

		for (IAction action : actions) {
			sb.append(String.format("* Action: %s\r\n", action.getClass().getName()));

			for (String name : action.getParameterMap().keySet()) {
				String value = action.getParameter(name);

				sb.append(String.format("*\tParameter: %s = %s\r\n", name, value));
			}
		}
		sb.append("*****************************************************\r\n");

		return sb.toString();
	}

	private boolean isAjaxRequest(HttpServletRequest request) {
		return request.getHeader("X-Requested-With") != null;
	}

	private void verifyAjaxToken(HttpServletRequest request) throws CsrfGuardException {
		HttpSession session = request.getSession(true);
		String tokenFromSession = (String) session.getAttribute(getSessionKey());
		String tokenFromRequest = request.getHeader(getTokenName());

		if (tokenFromRequest == null) {
			/** FAIL: token is missing from the request **/
			throw new CsrfGuardException("required token is missing from the request");
		} else if (!tokenFromSession.equals(tokenFromRequest)) {
			/** FAIL: the request token does not match the session token **/
			throw new CsrfGuardException("request token does not match session token");
		}
	}

	private void verifyPageToken(HttpServletRequest request) throws CsrfGuardException {
		HttpSession session = request.getSession(true);
		@SuppressWarnings("unchecked")
		Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

		String tokenFromPages = (pageTokens != null ? pageTokens.get(request.getRequestURI()) : null);
		String tokenFromSession = (String) session.getAttribute(getSessionKey());
		String tokenFromRequest = request.getParameter(getTokenName());

		if (tokenFromRequest == null) {
			/** FAIL: token is missing from the request **/
			throw new CsrfGuardException("required token is missing from the request");
		} else if (tokenFromPages != null) {
			if (!tokenFromPages.equals(tokenFromRequest)) {
				/** FAIL: request does not match page token **/
				throw new CsrfGuardException("request token does not match page token");
			}
		} else if (!tokenFromSession.equals(tokenFromRequest)) {
			/** FAIL: the request token does not match the session token **/
			throw new CsrfGuardException("request token does not match session token");
		}
	}

	private void verifySessionToken(HttpServletRequest request) throws CsrfGuardException {
		HttpSession session = request.getSession(true);
		String tokenFromSession = (String) session.getAttribute(getSessionKey());
		String tokenFromRequest = request.getParameter(getTokenName());

		if (tokenFromRequest == null) {
			/** FAIL: token is missing from the request **/
			throw new CsrfGuardException("required token is missing from the request");
		} else if (!tokenFromSession.equals(tokenFromRequest)) {
			/** FAIL: the request token does not match the session token **/
			throw new CsrfGuardException("request token does not match session token");
		}
	}

	private void rotateTokens(HttpServletRequest request) {
		HttpSession session = request.getSession(true);

		/** rotate master token **/
		String tokenFromSession = null;

		try {
			tokenFromSession = RandomGenerator.generateRandomId(getPrng(), getTokenLength());
		} catch (Exception e) {
			throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
		}

		session.setAttribute(getSessionKey(), tokenFromSession);

		/** rotate page token **/
		if (isTokenPerPageEnabled()) {
			@SuppressWarnings("unchecked")
			Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

			try {
				pageTokens.put(request.getRequestURI(), RandomGenerator.generateRandomId(getPrng(), getTokenLength()));
			} catch (Exception e) {
				throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
			}
		}
	}

	private boolean isUnprotectedPage(String uri) {
		boolean retval = false;

		for (String unprotectedPage : unprotectedPages) {
			if (isUriMatch(unprotectedPage, uri)) {
				retval = true;
				break;
			}
		}

		return retval;
	}

	/**
	 * FIXME: taken from Tomcat - ApplicationFilterFactory
	 * 
	 * @param testPath
	 * @param requestPath
	 * @return
	 */
	private boolean isUriMatch(String testPath, String requestPath) {
		boolean retval = false;

		/** Case 1: Exact Match **/
		if (testPath.equals(requestPath)) {
			retval = true;
		}

		/** Case 2 - Path Match ("/.../*") **/
		if (testPath.equals("/*")) {
			retval = true;
		}
		if (testPath.endsWith("/*")) {
			if (testPath
					.regionMatches(0, requestPath, 0, testPath.length() - 2)) {
				if (requestPath.length() == (testPath.length() - 2)) {
					retval = true;
				} else if ('/' == requestPath.charAt(testPath.length() - 2)) {
					retval = true;
				}
			}
		}

		/** Case 3 - Extension Match **/
		if (testPath.startsWith("*.")) {
			int slash = requestPath.lastIndexOf('/');
			int period = requestPath.lastIndexOf('.');

			if ((slash >= 0)
					&& (period > slash)
					&& (period != requestPath.length() - 1)
					&& ((requestPath.length() - period) == (testPath.length() - 1))) {
				retval = testPath.regionMatches(2, requestPath, period + 1,
						testPath.length() - 2);
			}
		}

		return retval;
	}
	
}
