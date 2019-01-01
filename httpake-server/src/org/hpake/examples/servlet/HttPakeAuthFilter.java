package org.hpake.examples.servlet;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.hpake.HttPakeException;
import org.hpake.SubjectConfirmation;
import org.hpake.Utils;
import org.hpake.protocol.Constants;
import org.hpake.protocol.Headers;

/**
 * Servlet filter responsible for handling HttPake authentication.
 * @author Wiraj Bibile
 */
public class HttPakeAuthFilter implements Filter
{
	/**
	 * JNDI name for the password function. 
	 */
	public static final String PASSWORD_FUNCTION = "password_function";
	private final Map<String, AuthHandler> sessionIdAuthHandlerMap = new ConcurrentHashMap<>();
	private final SecureRandom secureRandom = new SecureRandom();
	
	// Not volatile because this is assigned in init (init sets up happens before ordering)
	private Function<String, Object> passwordFunction;
	private volatile static HttPakeAuthFilter instance;
	
	private static SubjectConfirmation getSubjectConfirmation(HttpServletRequest request) throws HttPakeException
	{
		String confirmationString = request.getHeader(Headers.SUBJECT_CONFIRMATION);
		SubjectConfirmation result = null;
		if(confirmationString != null)
		{
			result = SubjectConfirmation.newInstance(confirmationString);
		}
		return result;
	}
	
	static void setChallenge(HttpServletResponse response, String challenge) throws  IOException
	{
		StringBuilder value = new StringBuilder(Constants.SCHEME);
		if(challenge != null)
		{
			value.append(Utils.VALUE_SEPARATOR).append(challenge);
		}
		response.setHeader(Headers.WWW_AUTHENTICATE, value.toString());
		response.sendError(401, "Unauthorized");

	}
	
	/**
	 * Create a new handler 
	 * @param user the user name
	 * @param passwordOrHash User password or hash
	 * @return the new AuthHandler.
	 */
	private AuthHandler createNewHandler(String user, char[] passwordOrHash) throws HttPakeException
	{
		boolean successful;
		AuthHandler result;
		do
		{
			String id = Utils.generateUUID();
			result = new AuthHandler(user, passwordOrHash, id, secureRandom);
			successful = sessionIdAuthHandlerMap.putIfAbsent(id, result) == null;
		}
		while(!successful);
		return result;
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)throws IOException, ServletException 
	{
		HttpServletRequest httpRequest = (HttpServletRequest)request;
		HttPakeServletResponseWrapper wrappedResponse = new HttPakeServletResponseWrapper((HttpServletResponse)response);
		
		try
		{
			doFilter(httpRequest, wrappedResponse, chain);
		}
		catch(HttPakeException e)
		{
			if(e.isServerError())
			{
				wrappedResponse.sendError(500, e.getMessage());
			}
			else
			{
				setChallenge(wrappedResponse, Constants.TRANSFORM_IDENTITY);
			}
		}
		finally
		{
			wrappedResponse.commitRequest();
		}
		
	}
	
	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws HttPakeException, IOException, ServletException
	{
		SubjectConfirmation clintSubjectConfirmation = getSubjectConfirmation(request);
		if(clintSubjectConfirmation == null)
		{
			// Request does not contain any session information.
			String authHeader = request.getHeader(Headers.AUTHORIZATION);
			if(authHeader == null)
			{
				throw new HttPakeException("User not authenticated.");
			}
			else
			{
				String[] parts = Utils.VALUE_SEPARATOR_PATTERN.split(authHeader, 2);
				if(parts.length == 2)
				{
					if(!parts[0].equals(Constants.SCHEME))
					{
						throw new HttPakeException("Invalid authentication scheme.");
					}
					String userName = parts[1];
					Object passwordOrHash = passwordFunction.apply(userName);
					if(passwordOrHash == null)
					{
						throw new HttPakeException("Unknown user");
					}
					AuthHandler handler = createNewHandler(userName, passwordOrHash.toString().toCharArray());
					handler.processRequest(request, response, clintSubjectConfirmation/*=null*/);
				}
				else
				{
					throw new HttPakeException("Invalid authentication scheme.");
				}
			}
		}
		else
		{
			handleRequest(clintSubjectConfirmation, request, response, chain);
		}
	}
	
	private void handleRequest(SubjectConfirmation clintSubjectConfirmation, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException
	{
		String sessionId = clintSubjectConfirmation.getSessionId();
		AuthHandler handler = sessionIdAuthHandlerMap.get(sessionId);
		if(handler == null)
		{
			throw new HttPakeException("User not authenticated.");
		}
		try 
		{
			if(!handler.processRequest(request, response, clintSubjectConfirmation))
			{
				chain.doFilter(request, response);
				handler.postProcessRequestNotHandled(request, response);
			}
		} 
		catch (HttPakeException e) 
		{
			sessionIdAuthHandlerMap.remove(sessionId);
			throw e;
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void init(FilterConfig filterConfig) throws ServletException 
	{
		// Initialize the password function.
		Object passwordFunctionValue;
		try
		{
			passwordFunctionValue = new InitialContext().lookup(PASSWORD_FUNCTION);
		} 
		catch (NamingException e1) 
		{
			throw new ServletException(PASSWORD_FUNCTION+" not configured.");
		}
		if(passwordFunctionValue instanceof Function)
		{
			passwordFunction = (Function<String,Object>) filterConfig.getServletContext().getAttribute(PASSWORD_FUNCTION);
			try
			{
				passwordFunction.apply("test");
			}
			catch(ClassCastException e)
			{
				throw new ServletException("The configured "+PASSWORD_FUNCTION+" is not valid.");
			}
		}
		else
		{
			throw new ServletException("The configured "+PASSWORD_FUNCTION+" is not valid.");
		}
		instance = this;
	}
	
	// @UsedBy("tests")
	public static HttPakeAuthFilter getInstance()
	{
		return instance;
	}
	
	/**
	 * Remove a session.
	 * @param sessionId The session ID
	 * @return true if the session was removed
	 */
	// @UsedBy("tests") 
	public boolean removeSession(String sessionId)
	{
		return sessionIdAuthHandlerMap.remove(sessionId) != null;
	}

	@Override
	public void destroy() 
	{
		// 
		
	}
}
