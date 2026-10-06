package org.cysecurity.cspf.jvl.controller;

/*
 * Tests for CWE-306 fix: Missing Authentication for Critical Function
 *
 * The Install servlet performs critical operations (database creation, admin
 * account provisioning, config file overwrite) that must be guarded so they
 * can only run once, before the application is configured.  After the first
 * successful installation the servlet must reject all subsequent requests with
 * HTTP 403 Forbidden.
 *
 * These tests verify the installation guard by exercising the Install servlet
 * through the real processRequest code path using lightweight stub
 * implementations of HttpServletRequest, HttpServletResponse, and
 * ServletContext — no external mocking framework required.
 */

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import junit.framework.TestCase;

/**
 * Unit tests for the Install servlet's authentication guard (CWE-306 fix).
 *
 * Strategy: write a temporary config.properties file with controlled
 * "installed" flag values, then invoke processRequest via reflection and
 * inspect the HTTP status code set on the response stub.
 */
public class InstallTest extends TestCase {

    // -----------------------------------------------------------------------
    // Minimal stub implementations
    // -----------------------------------------------------------------------

    /** Captures the status code and error message sent via sendError(). */
    private static class StubHttpServletResponse implements HttpServletResponse {
        private int statusCode = 200;
        private String errorMessage = null;
        private String contentType = null;
        private final StringWriter bodyWriter = new StringWriter();
        private final PrintWriter printWriter = new PrintWriter(bodyWriter);
        private boolean committed = false;

        public int getStatusCode()   { return statusCode; }
        public String getErrorMessage() { return errorMessage; }
        public StringWriter getBodyWriter() { return bodyWriter; }

        @Override public void sendError(int sc, String msg) throws IOException {
            this.statusCode = sc;
            this.errorMessage = msg;
            this.committed = true;
        }
        @Override public void sendError(int sc) throws IOException {
            this.statusCode = sc;
            this.committed = true;
        }
        @Override public void setStatus(int sc) { this.statusCode = sc; }
        @Override public void setContentType(String ct) { this.contentType = ct; }
        @Override public PrintWriter getWriter() throws IOException { return printWriter; }
        @Override public boolean isCommitted() { return committed; }

        // Unused interface methods - minimal stubs
        @Override public void addCookie(Cookie c) {}
        @Override public boolean containsHeader(String n) { return false; }
        @Override public String encodeURL(String url) { return url; }
        @Override public String encodeRedirectURL(String url) { return url; }
        @Override public String encodeUrl(String url) { return url; }
        @Override public String encodeRedirectUrl(String url) { return url; }
        @Override public void sendRedirect(String location) throws IOException {}
        @Override public void setDateHeader(String n, long d) {}
        @Override public void addDateHeader(String n, long d) {}
        @Override public void setHeader(String n, String v) {}
        @Override public void addHeader(String n, String v) {}
        @Override public void setIntHeader(String n, int v) {}
        @Override public void addIntHeader(String n, int v) {}
        @Override public void setStatus(int sc, String msg) {}
        @Override public String getCharacterEncoding() { return "UTF-8"; }
        @Override public java.io.OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
        @Override public void setCharacterEncoding(String c) {}
        @Override public void setContentLength(int l) {}
        @Override public void setBufferSize(int s) {}
        @Override public int getBufferSize() { return 0; }
        @Override public void flushBuffer() {}
        @Override public void resetBuffer() {}
        @Override public void reset() {}
        @Override public void setLocale(java.util.Locale l) {}
        @Override public java.util.Locale getLocale() { return java.util.Locale.getDefault(); }
    }

    /** Minimal request stub — returns parameters from an internal map. */
    private static class StubHttpServletRequest implements HttpServletRequest {
        private final Map<String, String> params = new HashMap<String, String>();

        public void setParameter(String name, String value) {
            params.put(name, value);
        }

        @Override public String getParameter(String name) { return params.get(name); }
        @Override public String getMethod() { return "POST"; }

        // Unused interface methods — minimal stubs
        @Override public String getAuthType() { return null; }
        @Override public Cookie[] getCookies() { return new Cookie[0]; }
        @Override public long getDateHeader(String n) { return -1; }
        @Override public String getHeader(String n) { return null; }
        @Override public Enumeration getHeaders(String n) { return new Vector().elements(); }
        @Override public Enumeration getHeaderNames() { return new Vector().elements(); }
        @Override public int getIntHeader(String n) { return -1; }
        @Override public String getPathInfo() { return null; }
        @Override public String getPathTranslated() { return null; }
        @Override public String getContextPath() { return ""; }
        @Override public String getQueryString() { return null; }
        @Override public String getRemoteUser() { return null; }
        @Override public boolean isUserInRole(String r) { return false; }
        @Override public java.security.Principal getUserPrincipal() { return null; }
        @Override public String getRequestedSessionId() { return null; }
        @Override public String getRequestURI() { return "/Install"; }
        @Override public StringBuffer getRequestURL() { return new StringBuffer("/Install"); }
        @Override public String getServletPath() { return "/Install"; }
        @Override public HttpSession getSession(boolean b) { return null; }
        @Override public HttpSession getSession() { return null; }
        @Override public boolean isRequestedSessionIdValid() { return false; }
        @Override public boolean isRequestedSessionIdFromCookie() { return false; }
        @Override public boolean isRequestedSessionIdFromURL() { return false; }
        @Override public boolean isRequestedSessionIdFromUrl() { return false; }
        @Override public String getAttribute(String n) { return null; }
        @Override public Enumeration getAttributeNames() { return new Vector().elements(); }
        @Override public String getCharacterEncoding() { return "UTF-8"; }
        @Override public void setCharacterEncoding(String e) {}
        @Override public int getContentLength() { return 0; }
        @Override public String getContentType() { return null; }
        @Override public javax.servlet.ServletInputStream getInputStream() { return null; }
        @Override public java.util.Map getParameterMap() { return params; }
        @Override public Enumeration getParameterNames() { return new Vector(params.keySet()).elements(); }
        @Override public String[] getParameterValues(String n) {
            String v = params.get(n); return v == null ? null : new String[]{v};
        }
        @Override public String getProtocol() { return "HTTP/1.1"; }
        @Override public String getScheme() { return "http"; }
        @Override public String getServerName() { return "localhost"; }
        @Override public int getServerPort() { return 8080; }
        @Override public java.io.BufferedReader getReader() { return null; }
        @Override public String getRemoteAddr() { return "127.0.0.1"; }
        @Override public String getRemoteHost() { return "localhost"; }
        @Override public void setAttribute(String n, Object v) {}
        @Override public void removeAttribute(String n) {}
        @Override public java.util.Locale getLocale() { return java.util.Locale.getDefault(); }
        @Override public Enumeration getLocales() { return new Vector().elements(); }
        @Override public boolean isSecure() { return false; }
        @Override public RequestDispatcher getRequestDispatcher(String p) { return null; }
        @Override public String getRealPath(String p) { return null; }
        @Override public int getRemotePort() { return 0; }
        @Override public String getLocalName() { return "localhost"; }
        @Override public String getLocalAddr() { return "127.0.0.1"; }
        @Override public int getLocalPort() { return 8080; }
    }

    /** Minimal ServletContext stub that returns a known real path for config.properties. */
    private static class StubServletContext implements ServletContext {
        private final String configDir;

        StubServletContext(String configDir) { this.configDir = configDir; }

        @Override public String getRealPath(String path) {
            // Map /WEB-INF/config.properties to the temp config file used in tests
            if ("/WEB-INF/config.properties".equals(path)) {
                return configDir + File.separator + "config.properties";
            }
            return configDir + path;
        }

        // Unused interface methods — minimal stubs
        @Override public String getContextPath() { return ""; }
        @Override public ServletContext getContext(String uri) { return null; }
        @Override public int getMajorVersion() { return 2; }
        @Override public int getMinorVersion() { return 3; }
        @Override public String getMimeType(String f) { return null; }
        @Override public java.util.Set getResourcePaths(String p) { return null; }
        @Override public java.net.URL getResource(String p) { return null; }
        @Override public java.io.InputStream getResourceAsStream(String p) { return null; }
        @Override public RequestDispatcher getRequestDispatcher(String p) { return null; }
        @Override public RequestDispatcher getNamedDispatcher(String n) { return null; }
        @Override public javax.servlet.Servlet getServlet(String n) { return null; }
        @Override public Enumeration getServlets() { return new Vector().elements(); }
        @Override public Enumeration getServletNames() { return new Vector().elements(); }
        @Override public void log(String msg) {}
        @Override public void log(Exception e, String msg) {}
        @Override public void log(String msg, Throwable t) {}
        @Override public String getServerInfo() { return "Test/1.0"; }
        @Override public String getInitParameter(String n) { return null; }
        @Override public Enumeration getInitParameterNames() { return new Vector().elements(); }
        @Override public Object getAttribute(String n) { return null; }
        @Override public Enumeration getAttributeNames() { return new Vector().elements(); }
        @Override public void setAttribute(String n, Object v) {}
        @Override public void removeAttribute(String n) {}
        @Override public String getServletContextName() { return "Test"; }
    }

    /** Minimal ServletConfig stub that delegates getRealPath to the stub context. */
    private static class StubServletConfig implements ServletConfig {
        private final StubServletContext context;

        StubServletConfig(String configDir) {
            this.context = new StubServletContext(configDir);
        }

        @Override public String getServletName() { return "Install"; }
        @Override public ServletContext getServletContext() { return context; }
        @Override public String getInitParameter(String n) { return null; }
        @Override public Enumeration getInitParameterNames() { return new Vector().elements(); }
    }

    // -----------------------------------------------------------------------
    // Test infrastructure helpers
    // -----------------------------------------------------------------------

    private File tempConfigDir;
    private File tempConfigFile;

    /**
     * Write a config.properties with the given "installed" value to the temp
     * directory used by the servlet during the test.
     */
    private void writeConfig(String installedValue) throws IOException {
        Properties p = new Properties();
        p.setProperty("dburl", "jdbc:mysql://localhost:3306/");
        p.setProperty("jdbcdriver", "com.mysql.jdbc.Driver");
        p.setProperty("dbuser", "testuser");
        p.setProperty("dbpass", "testpass");
        p.setProperty("dbname", "testdb");
        p.setProperty("siteTitle", "Test");
        if (installedValue != null) {
            p.setProperty("installed", installedValue);
        }
        FileOutputStream fos = new FileOutputStream(tempConfigFile);
        p.store(fos, null);
        fos.close();
    }

    /**
     * Read the "installed" property from the temp config file as written by
     * the servlet under test.
     */
    private String readInstalledFlag() throws IOException {
        Properties p = new Properties();
        FileInputStream fis = new FileInputStream(tempConfigFile);
        p.load(fis);
        fis.close();
        return p.getProperty("installed");
    }

    /**
     * Build an Install servlet wired to the temp config directory and invoke
     * processRequest via reflection (it is protected).
     */
    private Install buildServlet() throws Exception {
        Install servlet = new Install();
        StubServletConfig config = new StubServletConfig(tempConfigDir.getAbsolutePath());
        servlet.init(config);
        return servlet;
    }

    private void invokeProcessRequest(Install servlet,
                                      HttpServletRequest req,
                                      HttpServletResponse resp) throws Exception {
        Method m = Install.class.getDeclaredMethod(
                "processRequest", HttpServletRequest.class, HttpServletResponse.class);
        m.setAccessible(true);
        m.invoke(servlet, req, resp);
    }

    // -----------------------------------------------------------------------
    // JUnit 3.x setUp / tearDown
    // -----------------------------------------------------------------------

    @Override
    protected void setUp() throws Exception {
        // Create a temporary directory to hold the config.properties file
        tempConfigDir = new File(System.getProperty("java.io.tmpdir"),
                "jvl-install-test-" + System.nanoTime());
        assertTrue("Failed to create temp config dir", tempConfigDir.mkdirs());
        tempConfigFile = new File(tempConfigDir, "config.properties");
    }

    @Override
    protected void tearDown() throws Exception {
        // Clean up temp files
        if (tempConfigFile != null && tempConfigFile.exists()) {
            tempConfigFile.delete();
        }
        if (tempConfigDir != null && tempConfigDir.exists()) {
            tempConfigDir.delete();
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /**
     * POSITIVE TEST: When installed=false the endpoint must allow the request
     * to proceed (i.e. must NOT immediately return 403).
     *
     * Because we are not providing real DB credentials the request will fail
     * at the DB connection stage, but the guard code path (lines 59-65 of the
     * fixed Install.java) must not block it.  We verify that sendError(403)
     * was NOT called.
     */
    public void testAllowsRequestWhenNotYetInstalled() throws Exception {
        // Arrange: installed=false in config
        writeConfig("false");

        Install servlet = buildServlet();
        StubHttpServletRequest req = new StubHttpServletRequest();
        req.setParameter("dburl", "jdbc:mysql://localhost:3306/");
        req.setParameter("jdbcdriver", "com.mysql.jdbc.Driver");
        req.setParameter("dbuser", "testuser");
        req.setParameter("dbpass", "testpass");
        req.setParameter("dbname", "testdb");
        req.setParameter("siteTitle", "Test");
        req.setParameter("adminuser", "admin");
        req.setParameter("adminpass", "password");
        req.setParameter("setup", "1");

        StubHttpServletResponse resp = new StubHttpServletResponse();

        // Act: invoke the critical function — may throw due to missing DB; that is fine
        try {
            invokeProcessRequest(servlet, req, resp);
        } catch (Exception ignored) {
            // DB connection errors are expected in unit test context
        }

        // Assert: the guard must NOT have rejected the request with 403
        assertFalse(
            "Request must not be blocked with 403 when installed=false",
            resp.getStatusCode() == HttpServletResponse.SC_FORBIDDEN);
    }

    /**
     * SECURITY TEST (regression guard): When installed=true the endpoint MUST
     * return HTTP 403 Forbidden without touching any user-supplied parameters.
     * This directly exercises the CWE-306 fix at the taint source.
     */
    public void testBlocksRequestWhenAlreadyInstalled() throws Exception {
        // Arrange: installed=true simulates a previously configured system
        writeConfig("true");

        Install servlet = buildServlet();
        StubHttpServletRequest req = new StubHttpServletRequest();
        // Supply all parameters an attacker would send to reinitialise the DB
        req.setParameter("dburl", "jdbc:mysql://localhost:3306/");
        req.setParameter("jdbcdriver", "com.mysql.jdbc.Driver");
        req.setParameter("dbuser", "malicioususer");
        req.setParameter("dbpass", "maliciouspass");
        req.setParameter("dbname", "hackeddb");
        req.setParameter("siteTitle", "Hacked");
        req.setParameter("adminuser", "attacker");
        req.setParameter("adminpass", "attackerpass");
        req.setParameter("setup", "1");

        StubHttpServletResponse resp = new StubHttpServletResponse();

        // Act
        invokeProcessRequest(servlet, req, resp);

        // Assert: servlet MUST respond with 403
        assertEquals(
            "Install endpoint must return HTTP 403 when application is already installed",
            HttpServletResponse.SC_FORBIDDEN,
            resp.getStatusCode());
    }

    /**
     * SECURITY TEST: Attacker must not be able to bypass the guard by omitting
     * the "installed" parameter — the guard reads from the server-side config,
     * not from the request.  This test ensures a GET with no parameters still
     * triggers the 403 guard when installed=true.
     */
    public void testBlocksGetRequestWhenAlreadyInstalled() throws Exception {
        writeConfig("true");

        Install servlet = buildServlet();
        StubHttpServletRequest req = new StubHttpServletRequest();
        // No parameters supplied — simulates attacker probing the endpoint

        StubHttpServletResponse resp = new StubHttpServletResponse();

        invokeProcessRequest(servlet, req, resp);

        assertEquals(
            "Install GET request must be blocked with 403 when already installed",
            HttpServletResponse.SC_FORBIDDEN,
            resp.getStatusCode());
    }

    /**
     * CONFIG TEST: The config.properties must contain installed=false before
     * the first installation (verifies the initial state set up by the fix).
     */
    public void testConfigHasInstalledFalseByDefault() throws Exception {
        // Read the actual shipped config.properties from the WEB-INF directory
        // (relative to the Maven project root, this is under src/main/webapp)
        String projectRoot = System.getProperty("user.dir");
        File shippedConfig = new File(projectRoot,
                "src/main/webapp/WEB-INF/config.properties");

        if (!shippedConfig.exists()) {
            // Running from a different working directory — skip gracefully
            return;
        }

        Properties p = new Properties();
        FileInputStream fis = new FileInputStream(shippedConfig);
        p.load(fis);
        fis.close();

        assertEquals(
            "Shipped config.properties must have installed=false so that the " +
            "first-time installation is allowed",
            "false",
            p.getProperty("installed"));
    }

    /**
     * STATE TEST: Once processRequest runs when installed=false (and then
     * fails at DB setup due to missing DB in test environment), the config
     * must have been written with installed=true so that a subsequent call
     * is blocked.
     *
     * Note: This verifies the flag-writing side of the fix even when the DB
     * portion throws an exception, because the flag is set before the DB call.
     */
    public void testInstalledFlagIsPersistedToConfigAfterFirstRun() throws Exception {
        writeConfig("false");

        Install servlet = buildServlet();
        StubHttpServletRequest req = new StubHttpServletRequest();
        req.setParameter("dburl", "jdbc:mysql://localhost:3306/");
        req.setParameter("jdbcdriver", "com.mysql.jdbc.Driver");
        req.setParameter("dbuser", "testuser");
        req.setParameter("dbpass", "testpass");
        req.setParameter("dbname", "testdb");
        req.setParameter("siteTitle", "Test");
        req.setParameter("adminuser", "admin");
        req.setParameter("adminpass", "password");
        req.setParameter("setup", "1");

        StubHttpServletResponse resp = new StubHttpServletResponse();

        try {
            invokeProcessRequest(servlet, req, resp);
        } catch (Exception ignored) {
            // DB failures expected — we are testing config file state only
        }

        // Assert: the config should have installed=true after processRequest
        assertEquals(
            "Config must record installed=true after processRequest runs",
            "true",
            readInstalledFlag());
    }

    /**
     * DOUBLE-INVOCATION TEST: Two sequential calls to processRequest where the
     * first call writes installed=true must result in the second call being
     * blocked with 403, proving that the guard survives across request
     * boundaries within the same JVM.
     */
    public void testSecondInvocationIsBlocked() throws Exception {
        writeConfig("false");

        Install servlet = buildServlet();

        StubHttpServletRequest req1 = new StubHttpServletRequest();
        req1.setParameter("dburl", "jdbc:mysql://localhost:3306/");
        req1.setParameter("jdbcdriver", "com.mysql.jdbc.Driver");
        req1.setParameter("dbuser", "testuser");
        req1.setParameter("dbpass", "testpass");
        req1.setParameter("dbname", "testdb");
        req1.setParameter("siteTitle", "Test");
        req1.setParameter("adminuser", "admin");
        req1.setParameter("adminpass", "password");
        req1.setParameter("setup", "1");

        StubHttpServletResponse resp1 = new StubHttpServletResponse();

        // First call — allowed (may fail at DB, but flag is written)
        try {
            invokeProcessRequest(servlet, req1, resp1);
        } catch (Exception ignored) {}

        // Second call — must be blocked because installed=true was persisted
        StubHttpServletRequest req2 = new StubHttpServletRequest();
        req2.setParameter("dburl", "jdbc:mysql://localhost:3306/");
        req2.setParameter("jdbcdriver", "com.mysql.jdbc.Driver");
        req2.setParameter("dbuser", "malicioususer");
        req2.setParameter("dbpass", "maliciouspass");
        req2.setParameter("dbname", "hackeddb");
        req2.setParameter("siteTitle", "Hacked");
        req2.setParameter("adminuser", "attacker");
        req2.setParameter("adminpass", "attackerpass");
        req2.setParameter("setup", "1");

        StubHttpServletResponse resp2 = new StubHttpServletResponse();
        invokeProcessRequest(servlet, req2, resp2);

        assertEquals(
            "Second install attempt must be blocked with 403",
            HttpServletResponse.SC_FORBIDDEN,
            resp2.getStatusCode());
    }
}
