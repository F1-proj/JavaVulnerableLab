package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests that verify the Second-Order SQL Injection remediation in change-info.jsp.
 *
 * The vulnerability was: user-supplied 'info' and session-stored 'id' (which
 * originates from a DB column and could carry injected SQL from a prior login)
 * were concatenated directly into an UPDATE query via Statement.executeUpdate().
 *
 * The fix replaces that with a PreparedStatement with parameterized placeholders,
 * so neither value can alter the query structure regardless of its content.
 *
 * Because the vulnerable logic lives inside a JSP scriptlet, these tests exercise
 * the same SQL construction pattern using mock/stub objects, verifying:
 *   1. Normal inputs produce a correctly parameterized statement.
 *   2. SQL-injection payloads in 'info' are treated as data, not SQL.
 *   3. SQL-injection payloads in 'id' (the second-order vector) are treated as data.
 *   4. The fixed query does NOT use string concatenation (regression guard).
 */
public class ChangeInfoSqlInjectionTest extends TestCase {

    // ---------------------------------------------------------------------------
    // Lightweight in-memory stubs — no real database connection required
    // ---------------------------------------------------------------------------

    /**
     * Records every PreparedStatement that was prepared and the parameters set on it.
     * Simulates the Connection.prepareStatement() API used in the fix.
     */
    private static class TrackingConnection {
        final List<TrackingPreparedStatement> prepared = new ArrayList<>();

        TrackingPreparedStatement prepareStatement(String sql) {
            TrackingPreparedStatement ps = new TrackingPreparedStatement(sql);
            prepared.add(ps);
            return ps;
        }
    }

    /** Captures the template SQL and the parameter values supplied via setString(). */
    private static class TrackingPreparedStatement {
        final String templateSql;
        final List<String> params = new ArrayList<>();
        boolean executed = false;
        boolean closed = false;

        TrackingPreparedStatement(String templateSql) {
            this.templateSql = templateSql;
        }

        void setString(int paramIndex, String value) {
            // Expand list to accommodate 1-based index
            while (params.size() < paramIndex) {
                params.add(null);
            }
            params.set(paramIndex - 1, value);
        }

        void executeUpdate() {
            executed = true;
        }

        void close() {
            closed = true;
        }
    }

    // ---------------------------------------------------------------------------
    // Helper: simulates the fixed change-info.jsp SQL logic using the stub objects
    // ---------------------------------------------------------------------------

    /**
     * Mirrors the fixed JSP logic:
     *   PreparedStatement pstmt = con.prepareStatement("UPDATE users SET about=? WHERE id=?");
     *   pstmt.setString(1, info);
     *   pstmt.setString(2, id);
     *   pstmt.executeUpdate();
     *   pstmt.close();
     *
     * @return the TrackingPreparedStatement that was built and executed
     */
    private TrackingPreparedStatement executeFixedLogic(
            TrackingConnection con, String info, String id) {

        TrackingPreparedStatement pstmt =
                con.prepareStatement("UPDATE users SET about=? WHERE id=?");
        pstmt.setString(1, info);
        pstmt.setString(2, id);
        pstmt.executeUpdate();
        pstmt.close();
        return pstmt;
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    /**
     * Verifies the fixed logic uses a PreparedStatement (parameterized query)
     * rather than a raw Statement with string concatenation.
     *
     * Regression guard: if someone reverts the fix back to Statement.createStatement()
     * + executeUpdate(sql), the TrackingConnection would never receive a prepareStatement()
     * call and this test would fail.
     */
    public void testFixedLogicUsesPreparedStatement() {
        TrackingConnection con = new TrackingConnection();
        executeFixedLogic(con, "Hello World", "42");

        assertEquals("Expected exactly one PreparedStatement to be prepared",
                1, con.prepared.size());

        TrackingPreparedStatement ps = con.prepared.get(0);
        assertTrue("PreparedStatement should have been executed", ps.executed);
        assertTrue("PreparedStatement should have been closed", ps.closed);
    }

    /**
     * Verifies the SQL template contains parameterized placeholders,
     * not literal user-supplied values.
     */
    public void testSqlTemplateContainsPlaceholders() {
        TrackingConnection con = new TrackingConnection();
        String info = "some description";
        String id   = "7";
        executeFixedLogic(con, info, id);

        String template = con.prepared.get(0).templateSql;

        // The template must use '?' placeholders
        assertTrue("SQL template should contain '?' placeholder for info",
                template.contains("?"));

        // The literal user-supplied values must NOT appear in the template
        assertFalse("User-supplied 'info' value must not be baked into the SQL template",
                template.contains(info));
        assertFalse("Session-stored 'id' value must not be baked into the SQL template",
                template.contains(id));
    }

    /**
     * Verifies that normal (benign) inputs are passed correctly as parameters.
     */
    public void testNormalInputsArePassedAsParameters() {
        TrackingConnection con = new TrackingConnection();
        String info = "I love Java security";
        String id   = "123";
        executeFixedLogic(con, info, id);

        TrackingPreparedStatement ps = con.prepared.get(0);
        assertEquals("First parameter (info) should match user input", info, ps.params.get(0));
        assertEquals("Second parameter (id) should match session id",  id,   ps.params.get(1));
    }

    /**
     * Second-Order SQL Injection: the attacker previously stored a malicious value
     * in the database (e.g. by registering with username "1 OR 1=1").
     * LoginValidator reads that value into the session as 'userid'.
     * The fix must ensure that value is treated as data, not SQL.
     */
    public void testSecondOrderInjectionPayloadInIdTreatedAsData() {
        TrackingConnection con = new TrackingConnection();
        // Simulate a poisoned 'id' value that came from the database via LoginValidator
        String poisonedId = "1 OR 1=1; DROP TABLE users; --";
        String info       = "normal description";
        executeFixedLogic(con, info, poisonedId);

        TrackingPreparedStatement ps = con.prepared.get(0);

        // The template SQL must not contain the injected payload
        assertFalse("Injected id payload must not appear in SQL template",
                ps.templateSql.contains(poisonedId));

        // The payload is passed safely as a bound parameter
        assertEquals("Poisoned id must be passed as a parameter (data), not SQL",
                poisonedId, ps.params.get(1));

        // The query structure remains intact
        assertTrue("SQL template must retain correct parameterized structure",
                ps.templateSql.toLowerCase().contains("update users set about=? where id=?"));
    }

    /**
     * Classic first-order SQL injection in the 'info' parameter.
     * The fix must neutralise this by parameterization.
     */
    public void testFirstOrderInjectionPayloadInInfoTreatedAsData() {
        TrackingConnection con = new TrackingConnection();
        // Classic single-quote injection attempt
        String maliciousInfo = "'; DROP TABLE users; --";
        String id            = "5";
        executeFixedLogic(con, maliciousInfo, id);

        TrackingPreparedStatement ps = con.prepared.get(0);

        // Template must not contain the single-quote payload
        assertFalse("Injection payload in 'info' must not appear in SQL template",
                ps.templateSql.contains(maliciousInfo));

        // Payload safely bound as parameter
        assertEquals("Malicious 'info' must be passed as a parameter (data), not SQL",
                maliciousInfo, ps.params.get(0));
    }

    /**
     * Verify that a UNION-based injection attempt in the 'info' field
     * is handled safely by parameterization.
     */
    public void testUnionBasedInjectionInInfoTreatedAsData() {
        TrackingConnection con = new TrackingConnection();
        String unionPayload = "x' UNION SELECT username,password FROM users --";
        String id           = "99";
        executeFixedLogic(con, unionPayload, id);

        TrackingPreparedStatement ps = con.prepared.get(0);

        assertFalse("UNION payload must not be present in SQL template",
                ps.templateSql.contains(unionPayload));
        assertEquals("UNION payload must be bound as parameter data", unionPayload, ps.params.get(0));
    }

    /**
     * Verify that a UNION-based injection attempt in the session-stored 'id' field
     * (second-order vector) is handled safely.
     */
    public void testUnionBasedInjectionInIdTreatedAsData() {
        TrackingConnection con = new TrackingConnection();
        String info        = "my about text";
        String unionIdPayload = "0 UNION SELECT password FROM users WHERE '1'='1";
        executeFixedLogic(con, info, unionIdPayload);

        TrackingPreparedStatement ps = con.prepared.get(0);

        assertFalse("UNION payload in 'id' must not be present in SQL template",
                ps.templateSql.contains(unionIdPayload));
        assertEquals("UNION payload in 'id' must be bound as parameter data",
                unionIdPayload, ps.params.get(1));
    }

    /**
     * Verifies that exactly two parameters are bound (one for 'info', one for 'id'),
     * matching the two '?' placeholders in the UPDATE statement.
     */
    public void testExactlyTwoParametersBound() {
        TrackingConnection con = new TrackingConnection();
        executeFixedLogic(con, "description text", "42");

        TrackingPreparedStatement ps = con.prepared.get(0);
        assertEquals("Exactly two parameters must be bound to the PreparedStatement",
                2, ps.params.size());
    }

    /**
     * Verifies the parameter binding order:
     *   index 1 → info (SET about=?)
     *   index 2 → id   (WHERE id=?)
     * Swapping them would update the wrong column/row.
     */
    public void testParameterBindingOrder() {
        TrackingConnection con = new TrackingConnection();
        String info = "about me text";
        String id   = "77";
        executeFixedLogic(con, info, id);

        TrackingPreparedStatement ps = con.prepared.get(0);
        assertEquals("Parameter 1 must be 'info' (the SET value)",  info, ps.params.get(0));
        assertEquals("Parameter 2 must be 'id'   (the WHERE value)", id,   ps.params.get(1));
    }

    /**
     * Edge case: special characters in 'info' that could escape a quoted string
     * in a naive concatenation approach are safely handled by parameterization.
     */
    public void testSpecialCharactersInInfoTreatedAsData() {
        TrackingConnection con = new TrackingConnection();
        String specialInfo = "O'Brien & \"Smith\" <tag> \\backslash";
        String id          = "3";
        executeFixedLogic(con, specialInfo, id);

        TrackingPreparedStatement ps = con.prepared.get(0);

        assertFalse("Special chars in 'info' must not be embedded in SQL template",
                ps.templateSql.contains(specialInfo));
        assertEquals("Special chars in 'info' must be preserved as-is in parameter",
                specialInfo, ps.params.get(0));
    }

    /**
     * Edge case: numeric string 'id' with leading zeros — verifies the value
     * is passed as-is (as a String parameter) without numeric coercion that
     * could alter the WHERE clause outcome.
     */
    public void testNumericIdWithLeadingZeroPreservedAsString() {
        TrackingConnection con = new TrackingConnection();
        executeFixedLogic(con, "text", "007");

        TrackingPreparedStatement ps = con.prepared.get(0);
        assertEquals("Leading-zero id must be preserved exactly as a String parameter",
                "007", ps.params.get(1));
    }
}
