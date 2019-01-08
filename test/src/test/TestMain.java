package test;

import java.net.URI;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.servlet.DispatcherType;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.hpake.DHPublicKeyDTO;
import org.hpake.HttPakeException;
import org.hpake.Utils;
import org.hpake.examples.client.HttPakeClient;
import org.hpake.examples.client.HttPakeClient.AuthenticatedInfo;
import org.hpake.examples.client.RetryException;
import org.hpake.examples.client.UserCredentialInput;
import org.hpake.examples.servlet.HttPakeAuthFilter;
import org.hpake.protocol.Constants;

/**
 * Tests for HttPake.
 * TODO: Use JUnit.
 * @author Wiraj Bibile
 */
public class TestMain 
{
	private static final String urlPrefix = "http://localhost:8080";
	private static final Map<String,Object> passwordMap = createPasswordMap();
	
	
	public static void main(String[] args) throws Exception 
	{
		testPubicKeySynchronization();
		runSystemTests();
	}
	
	private static void testPubicKeySynchronization()
	{
		// two bytes with all bits set.
		byte data[] = new byte[2];
		data[0] =  -1;
		data[1] =  -1;
		
		testAssert(Utils.decodeBase64Unsigned(Base64.toBase64String(data)).longValue() == 65535L);
	}
	
	private static void setUpInitialContext() throws Exception
	{
		System.setProperty(Context.INITIAL_CONTEXT_FACTORY, "org.eclipse.jetty.jndi.InitialContextFactory");
		System.setProperty(Context.URL_PKG_PREFIXES, "org.eclipse.jetty");
		InitialContext ic = new InitialContext();
		ic.bind(org.hpake.examples.servlet.HttPakeAuthFilter.PASSWORD_FUNCTION, (Function<String, Object>)passwordMap::get);
	}
	
	private static void runSystemTests() throws Exception
	{
		setUpInitialContext();
		Server server = new Server(8080);
		ServletContextHandler  handler = new ServletContextHandler();
		handler.setAttribute(org.hpake.examples.servlet.HttPakeAuthFilter.PASSWORD_FUNCTION, (Function<String, Object>)passwordMap::get);
		handler.addFilter(HttPakeAuthFilter.class, "/*", EnumSet.of(DispatcherType.REQUEST));
		handler.addServlet(test.TestServlet.class, "/*");
		server.setHandler(handler);
		server.start();
		try
		{
			System.out.println("Test server started.");
			int count = 0;
			for(TestFunction f: getTests())
			{
				System.out.println("Running test "+(++count));
				f.doTest();
				// Reset data.
				TestServlet.servletData.clear();
			}
		}
		finally
		{
			server.stop();
		}
		
	}
	
	/**
	 * @return A list of tests to run
	 */
	private static List<TestFunction> getTests()
	{
		List<TestFunction> result = new ArrayList<>(10);
		result.add(TestMain::testSimpleAuthenticate);
		result.add(TestMain::testInvalidUser);
		result.add(TestMain::testInvalidPassword);
		result.add(TestMain::testSessionGone);
		result.add(TestMain::testUseOldRequestId);
		return result;
	}
	
	/**
	 * Runs a simple HttPake authentication sequence.
	 */
	private static void testSimpleAuthenticate() throws Exception
	{
		HttPakeClient client = createClient();
		testAssert(client.getAuthenticatedInfo() == null);
		String path = "/foo";
		CloseableHttpResponse result = get(path, client);
		AuthenticatedInfo authInfo = client.getAuthenticatedInfo();
		testAssert(authInfo != null);
		String sessionId = authInfo.getSessionId();
		testAssert(result.getStatusLine().getStatusCode() == 404);
		TestServlet.servletData.put(path, "bar");
		result = get(path, client);
		testAssert(sessionId.equals(client.getAuthenticatedInfo().getSessionId()));
		testAssert(result.getStatusLine().getStatusCode() == 200);
		testAssert("bar".equals(readData(result)));
	}

	
	/**
	 * Test the behavior when the user name is incorrect.
	 */
	private static void testInvalidUser() throws Exception
	{
		HttPakeClient client = createClient("non-existing-user", "bar");
		try
		{
			get("/foo", client);
			testAssert(false);
		}
		catch(HttPakeException e)
		{
			testAssert("Invalid user name.".equals(e.getMessage()));
		}
	}
	
	/**
	 * Test the behavior when the password is incorrect.
	 */
	private static void testInvalidPassword() throws Exception
	{
		String user = passwordMap.keySet().iterator().next(); 
		HttPakeClient client = createClient(user, passwordMap.get(user)+"x");
		try
		{
			get("/foo", client);
			testAssert(false);
		}
		catch(HttPakeException e)
		{
			testAssert("Authentication failed.".equals(e.getMessage()));
		}
	}
	
	/**
	 * Test the behavior when a existing session goes away.
	 */
	private static void testSessionGone() throws Exception
	{
		String path = "/bar";
		TestServlet.servletData.put(path, "baz");
		HttPakeClient client = createClient();
		CloseableHttpResponse response = get(path, client);
		testAssert("baz".equals(readData(response)));
		
		String firstSession = client.getAuthenticatedInfo().getSessionId();
		boolean removed = HttPakeAuthFilter.getInstance().removeSession(firstSession);
		testAssert(removed);
		
		response = get(path, client);
		testAssert("baz".equals(readData(response)));
		String secondSession = client.getAuthenticatedInfo().getSessionId();
		testAssert(!firstSession.equals(secondSession));
	}
	
	/**
	 * Test the behavior when attempting reuse a request ID. 
	 */
	private static void testUseOldRequestId() throws Exception
	{
		String path = "/baz";
		TestServlet.servletData.put(path, "qux");
		HttPakeClient client = createClient();
		
		// No request issued, therefore don't expect to see auth info.  
		testAssert(client.getAuthenticatedInfo() == null);
		
		// Force auth info to be created. 
		CloseableHttpResponse response = get(path, client);
		response.close();
		
        AuthenticatedInfo oldAuthInfo = new AuthenticatedInfo(client.getAuthenticatedInfo());
        String oldSessionId = client.getAuthenticatedInfo().getSessionId();
        
        // Issue a request
        response = get(path, client);
		response.close();
		// The session ID used in the previous request should be the same as the old session ID.
		testAssert(oldSessionId.equals(client.getAuthenticatedInfo().getSessionId()));
		// Request Ids are expected to change
		testAssert(!oldAuthInfo.getRequestId().equals(client.getAuthenticatedInfo().getRequestId()));
		
		// Set the copy of the old auth info. This forces the client use a previously used requestID.  
		client.setAuthInfo(oldAuthInfo);
		response = get(path, client);
		response.close();
		
		String newSessionId = client.getAuthenticatedInfo().getSessionId();
		
		// Should now be using a new session.  This because the first request issued by the previous get() call
		// was forced to use an old request ID, resulting in 401 and, subsequent creation of a new session.
		testAssert(!oldAuthInfo.getSessionId().equals(newSessionId));
		
		// Make sure that the old session Id does not exist.
		testAssert(!HttPakeAuthFilter.getInstance().removeSession(oldSessionId));
		
		// Make sure that the new session Id is known.
		testAssert(HttPakeAuthFilter.getInstance().removeSession(newSessionId));

	}
	
	/**
	 * Creates a new client. The new client is initialized to use valid credentials.
	 * @return the newly created client 
	 */
	private static HttPakeClient createClient() throws Exception
	{
		String user = passwordMap.keySet().iterator().next(); 
		return createClient(user, passwordMap.get(user));
	}
	
	
	/**
	 * Creates a new client.
	 * @param user Login user name
	 * @param password Login password 
	 * @return the newly created client
	 */
	private static HttPakeClient createClient(String user, Object password) throws Exception
	{
		HttpClientBuilder clientBuilder = HttpClientBuilder.create().useSystemProperties();
		// Uncomment the following code to capture traffic using fiddler proxy.
//         clientBuilder.setProxy(new org.apache.http.HttpHost("127.0.0.1", 8888, "http"));
		return new HttPakeClient(clientBuilder.build(), new TestUserCredentialInput(user, password), new URI(urlPrefix));
		
	}
	
	/**
	 * Issue a HTTP GET.
	 * @param path the relative path
	 * @param client the client
	 * @return The GET response
	 */
	private static CloseableHttpResponse get(String path, HttPakeClient client) throws Exception
	{
		String absPath = getAbsPath(path);
		CloseableHttpResponse result;
		try 
		{
			result = client.executeRequest(new HttpGet(absPath));
		}
		catch (RetryException e)
		{
			result = client.executeRequest(new HttpGet(absPath));
		}
		return result;
	}
	
	/**
	 * Converts a relative path to a 
	 * @param path
	 * @return
	 */
	private static String getAbsPath(String path)
	{
		return urlPrefix+path;
	}
	
	/**
	 * Test assertion. 
	 * @param test the test 
	 */
	private static void testAssert(boolean test)
	{
		if(!test)
		{
			throw new AssertionError("Test assertion failed.");
		}
	}
	
	/**
	 * Retrieves response data. Assumes that the response contains a UTF-8 string.
	 * @param response The response
	 * @return response data
	 */
	private static String readData(CloseableHttpResponse response) throws Exception
	{
		try(Scanner scanner = new Scanner(response.getEntity().getContent(), "UTF-8"))
		{
			scanner.useDelimiter("\\A");
			return scanner.hasNext()?  scanner.next(): null;
		}
	}
	
	private static Map<String,Object> createPasswordMap()
	{
		ConcurrentHashMap<String,Object> result = new ConcurrentHashMap<>();
		result.put("user1", "foobar");
		result.put("user2", "f00bar!");
		return result;
	}
	
	/**
	 * Definition for a test a function.
	 */
	@FunctionalInterface
	private static interface TestFunction
	{
		void doTest() throws Exception;
	}
	
	/**
	 * Credential input used by the client. 
	 */
	private static class TestUserCredentialInput implements UserCredentialInput
	{
		
		private final String userName;
		private final char[] password;

		TestUserCredentialInput(String userName, Object password)
		{
			this.userName = userName;
			this.password = password.toString().toCharArray();
		}

		@Override
		public char[] getPassword()
		{
			return password;
		}

		@Override
		public String getUserName() 
		{
			return userName;
		}
		
	}

}
