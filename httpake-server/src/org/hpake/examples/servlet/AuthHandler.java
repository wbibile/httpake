package org.hpake.examples.servlet;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.hpake.DHKeyPair;
import org.hpake.DHPublicKeyDTO;
import org.hpake.DHUtils;
import org.hpake.HttPakeException;
import org.hpake.IdStore;
import org.hpake.SubjectConfirmation;
import org.hpake.Utils;
import org.hpake.protocol.Constants;
import org.hpake.protocol.Headers;

/**
 * HttPake authentication handler. Responsible for handling authentication and maintaining a single session.
 * @author Wiraj Bibile
 */
public class AuthHandler 
{
	
	// States of the internal state machine.
	private enum State{USER_NAME_RECEIVED , PUBLIC_KEY_SENT, AUTHENTICATED}
	private static final BigInteger MAX_LONG = BigInteger.valueOf(Long.MAX_VALUE);
	
	final String sessionId;
	private final AtomicReference<State> currentStateRef = new AtomicReference<AuthHandler.State>(State.USER_NAME_RECEIVED);
	private final AtomicReference<byte[]> keyRef = new AtomicReference<>();
	private final AtomicLong responseIdRef = new AtomicLong();
	
	private final DHKeyPair keyPair;
	private final DHPublicKeyDTO serverPublicKeyDTO;
	
	private final SecureRandom random;
	private final IdStore requestIdStore = new IdStore(Constants.REQUEST_ID_BUFFER_SIZE);
	
	private final String sNonce;
	
    // @GuardedBy(this)
	// @CheckForNull
	private char[] passwordOrHash;
	
	
	/**
	 * @param userName The name of the user 
	 * @param passwordOrHash the users password or hash of the users passowrd
	 * @param sessionId
	 * @param random
	 * @throws HttPakeException
	 */
	AuthHandler(String userName, char[] passwordOrHash, String sessionId, SecureRandom random) throws HttPakeException
	{
		keyPair = DHUtils.generateKeyPair();
		serverPublicKeyDTO =  new DHPublicKeyDTO(keyPair.getPublicKey());
		this.passwordOrHash = passwordOrHash;
		this.sessionId = sessionId;
		this.random = random;
		this.sNonce = Utils.generateNonce();
	}
	
	/**
	 * Process a request
	 * @param request the servlet request to process
	 * @param response the servlet response
	 * @param clientSubjectConfirmation the subject confirmation or null if not available
	 * @return true if request was handled 
	 */
	public boolean processRequest(HttpServletRequest request, HttpServletResponse response, SubjectConfirmation clientSubjectConfirmation) throws HttPakeException
	{
		SubjectConfirmation serverSubjectConfirmation;
		boolean result = true;
		assert( currentStateRef.get() == AuthHandler.State.USER_NAME_RECEIVED || clientSubjectConfirmation != null);
		try
		{
			synchronized(this)
			{
				switch(currentStateRef.get())
				{
				case USER_NAME_RECEIVED:
					setPublicKey(response);
					setAndGetConfirmation(response);
					HttPakeAuthFilter.setChallenge(response, null);
					setState(State.USER_NAME_RECEIVED, State.PUBLIC_KEY_SENT);
					break;
				case PUBLIC_KEY_SENT:
					if(!requestIdStore.isEmpty())
					{
						throw new HttPakeException("Not initial request.");
					}
					long requestIdLong = checkAndGetRequestId(clientSubjectConfirmation);
					long expectedRequestId = getLastResponseId()+1;
					if(expectedRequestId != requestIdLong)
					{
						throw new HttPakeException("Unexpected request id");
					}
					deriveKey(request);
					verifySignature(request, clientSubjectConfirmation);
					serverSubjectConfirmation = setAndGetConfirmation(response);
					setSignature(response, serverSubjectConfirmation, 200);
					setState(State.PUBLIC_KEY_SENT, State.AUTHENTICATED);
					break;
				case AUTHENTICATED:
					checkAndGetRequestId(clientSubjectConfirmation);
					verifySignature(request, clientSubjectConfirmation);
					result = false;
					break;
				default :
					assert false: "Unknown state.";
				}			
			}
		} 
		catch (IOException e) 
		{
			throw new HttPakeException(e);
		}	
		return result;
	}

	private long checkAndGetRequestId(SubjectConfirmation clientSubjectConfirmation)
	{
		assert(clientSubjectConfirmation != null);
		assert(sessionId.equals(clientSubjectConfirmation.getSessionId()));
		BigInteger requestId = clientSubjectConfirmation.getRequestOrResponseId();
		if(requestId.compareTo(BigInteger.ZERO) < 0|| requestId.compareTo(MAX_LONG) > 0)
		{
			throw new HttPakeException("Request ID not within the supported range.");
		}
		requestIdStore.checkIdAndRemember(requestId);
		return requestId.longValueExact();
	}
	
	/**
	 * Post processes a request not handled by this handler.
	 * @param request The servlet request to post process
	 * @param response The servlet response
	 */
	public void postProcessRequestNotHandled(HttpServletRequest request, HttpServletResponse response) throws HttPakeException
	{
		assert (currentStateRef.get() == State.AUTHENTICATED): "Client must be authenticated.";
		SubjectConfirmation serverSubjectConfirmation = setAndGetConfirmation(response);
		setSignature(response, serverSubjectConfirmation, response.getStatus());
		
	}
	
	/**
	 * Set the public key header on the given response.
	 * @param response the response to set public key on 
	 */
	private void setPublicKey(HttpServletResponse response) throws IOException, HttPakeException 
	{
		response.setHeader(Headers.PUBLIC_KEY, new DHPublicKeyDTO(keyPair.getPublicKey()).getSerializationString());
	}

	/**
	 * Derive HttPake key by combining the client public-key, servers private-key, and the users password. 
	 * @param request The request
	 */
	private void deriveKey(HttpServletRequest request) throws HttPakeException
	{
		String publicKeyHeader = request.getHeader(Headers.PUBLIC_KEY);
		if(publicKeyHeader == null)
		{
			throw new HttPakeException(Headers.PUBLIC_KEY+ " header not specified");
		}
		
		// Combine the clients public-key and servers private-key to establish the Diffie-Hellmen shared secret.
		BigInteger clientYValue = Utils.decodeBase64Unsigned(publicKeyHeader);
		PublicKey clientPublicKey = serverPublicKeyDTO.derive(clientYValue).getPublicKey();
		byte[] secret = DHUtils.dhSecret(keyPair.getPrivateKey(), clientPublicKey);
		
		// Derive HttPake key by combining (HMAC-SHA256) DH secret with the users password. 
		byte[] keyBytes = Utils.deriveKey(getPasswordAndForget(), secret);
		if(!keyRef.compareAndSet(null, keyBytes))
		{
			// Looks like the state machine is out of step.
			throw new HttPakeException("Found previous key.").setAsServerError();
		}
	}
	
	/**
	 * Sets the state of this handler.
	 * @param expected the expected state 
	 * @param update the new state
	 */
	private void setState(State expected, State update) throws HttPakeException
	{
		
		assert(expected.ordinal() +1  == update.ordinal()): "Invalid state update from "+expected+" to "+update;
		if(!currentStateRef.compareAndSet(expected, update))
		{
			throw new HttPakeException("Authenticaation sequence out of step ");
		}
	}
	
	private void verifySignature(HttpServletRequest request, SubjectConfirmation clientSubjectConfirmation) throws HttPakeException
	{
		String givenClientSignature = request.getHeader(Headers.SIGNATURE);
		String computedClientSignature = clientSubjectConfirmation.getClientSignature(getKey());
		if(!computedClientSignature.equals(givenClientSignature))
		{
			throw new HttPakeException("Could not verify signature.");
		}
	}
	
	public SubjectConfirmation setAndGetConfirmation(HttpServletResponse response)
	{
		SubjectConfirmation confirmation = SubjectConfirmation.newInstance(nextResponseId(), sessionId, sNonce);
		response.setHeader(Headers.SUBJECT_CONFIRMATION, confirmation.getHeaderValue());
		return confirmation;
		
	}
	
	private void setSignature(HttpServletResponse response, SubjectConfirmation subjectConfirmation, int httpStatus) throws HttPakeException
	{
		response.setHeader(Headers.SIGNATURE, subjectConfirmation.serverSignature(getKey(), httpStatus));
	}
	
	private long nextResponseId()
	{
		long result = responseIdRef.get();
		if(result <= 0L)
		{
			int start;
			do
			{
				start = random.nextInt();
			}
			while(start < 0);
			
			responseIdRef.compareAndSet(0L, start);
		}
		return responseIdRef.incrementAndGet();
	}
	
	private long getLastResponseId()
	{
		return responseIdRef.get();
	}

	/**
	 * Get the HttPake key.
	 * @return The key
	 * @throws HttPakeException if the key is not set
	 */
	private byte[] getKey() throws HttPakeException
	{
		byte[] result = keyRef.get();
		if(result == null)
		{
			// Looks like the state machine is out of step.
			throw new HttPakeException("key not set").setAsServerError();
		}
		return result;
	}
	
	/**
	 * Gets the password and forgets it
	 * @return the password
	 * @throws HttPakeException if the password is not set
	 */
	private byte[] getPasswordAndForget() throws HttPakeException
	{
		assert Thread.holdsLock(this);
		if(passwordOrHash == null)
		{
			// Looks like the state machine is out of step.
			throw new HttPakeException("Password consumed.").setAsServerError();
		}
		String result = new String(passwordOrHash);
		passwordOrHash = null;
		return Utils.getUtf8Bytes(result);
	}
	
}
