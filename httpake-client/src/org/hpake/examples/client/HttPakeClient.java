package org.hpake.examples.client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey;
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
 * An HTTPake client based on the Apache HTTP client.
 * @author Wiraj Bibile
 *
 */
public class HttPakeClient 
{
	private final URI baseURI;
	private final CloseableHttpClient client;

	private final UserCredentialInput credentialInput;
	
	private final AtomicReference<AuthenticatedInfo> authInfoRef = new AtomicReference<>();
	private final String baseURIString;
	
	public HttPakeClient(UserCredentialInput credentialInput, URI baseURI)
	{
		this(HttpClientBuilder.create().build(), credentialInput, baseURI);
	}
	
	public HttPakeClient(CloseableHttpClient client ,UserCredentialInput credentialInput, URI baseURI)
	{
		this.credentialInput = credentialInput;
		this.baseURI = baseURI;
		this.baseURIString = baseURI.toString();
		this.client = client;
	}
	
	/**
	 * Executes a request.
	 * @param request The request 
	 * @return the response
	 * @throws RetryException if thrown the caller must retry the request. If the request has a entity body the request must be created from scratch. 
	 */
	public CloseableHttpResponse executeRequest(HttpRequestBase request) throws ClientProtocolException, IOException, HttPakeException, RetryException
	{
		if(!request.getURI().toString().startsWith(baseURIString))
		{
			throw new HttPakeException("Invalid request URI");
		}
		AuthenticatedInfo authInfo = authInfoRef.get();
		// If authenticated add HttPake headers.
		if(authInfo != null)
		{
			SubjectConfirmation clientConf = SubjectConfirmation.newInstance(authInfo.generateAndGetNextRequestId(), authInfo.getSessionId(), authInfo.getClietNonce());
			request.setHeader(Headers.SUBJECT_CONFIRMATION, clientConf.getHeaderValue());
			request.setHeader(Headers.SIGNATURE, clientConf.getClientSignature(authInfo.getHttPakeKey()));
		}

		CloseableHttpResponse response = client.execute(request);
		StatusLine line = response.getStatusLine();
		if(line.getStatusCode() == HttpStatus.SC_UNAUTHORIZED)
		{
			response.close();
			request.getURI();
			processAuth(baseURI, response);
			throw new RetryException();
 		}
		else if(authInfo == null)
		{
			throw new HttPakeException("HttPake challenge expected.");
		}
		else
		{
			validateServerSignature(response, authInfo);
		}
		return response;
	}
	
	private static String getHeader(HttpResponse res, String header)
	{
		Header h = res.getFirstHeader(header);
		if(h == null)
		{
			throw new HttPakeException("Header "+header+" expected.");
		}
		String result = h.getValue();
		if(result == null)
		{
			throw new HttPakeException("Header "+header+" expected.");
		}
		return result;
	}
	
	private void processAuth(URI uri, HttpResponse response) throws HttPakeException, IOException
	{
		String authHeader = getHeader(response, Headers.WWW_AUTHENTICATE);
		String[] parts = Utils.VALUE_SEPARATOR_PATTERN.split(authHeader, 2);
		if(parts.length != 2)
		{
			throw new HttPakeException( Headers.WWW_AUTHENTICATE+" header is invalid.");
		}
		if(!Constants.SCHEME.equals(parts[0]))
		{
			throw new HttPakeException("Invalid scheme "+parts[0]);
		}
		Function<String, byte[]> transform = getTransformFromName(parts[1]);
		sendUserNameAndContinueAuth(uri, transform);
	}
	
	private void sendUserNameAndContinueAuth(URI uri, Function<String,byte[]> passwordTransform) throws  IOException
	{
		HttpHead request2 = new HttpHead(uri);
		request2.setHeader(Headers.AUTHORIZATION, Constants.SCHEME+Utils.VALUE_SEPARATOR+credentialInput.getUserName());
		DHPublicKeyDTO serverPublicKey;
		SubjectConfirmation subjectConfirmation;
		try(CloseableHttpResponse response2 = client.execute(request2))
		{
			int status = response2.getStatusLine().getStatusCode();
			if (status != HttpStatus.SC_UNAUTHORIZED)
			{
				throw new HttPakeException("Unexpected status "+status+", expected "+HttpStatus.SC_UNAUTHORIZED);
			}
			String authHeader = getHeader(response2, Headers.WWW_AUTHENTICATE);
			
			String[] parts = Utils.VALUE_SEPARATOR_PATTERN.split(authHeader, 2);
			if(parts.length == 2)
			{
				// This means that the server reset the authentication sequence.
				// Note that in HttPake user names are not secret.
				throw new HttPakeException("Invalid user name.");
			}
			if(!Constants.SCHEME.equals(parts[0]))
			{
				throw new HttPakeException("Invalid scheme "+parts[0]);
			}
			
			serverPublicKey = DHPublicKeyDTO.fromSerializationString(getHeader(response2, Headers.PUBLIC_KEY));
			subjectConfirmation = SubjectConfirmation.newInstance(getHeader(response2, Headers.SUBJECT_CONFIRMATION));
		}
		String sessionId = subjectConfirmation.getSessionId();
		
		DHKeyPair clientKeyPair = DHUtils.generateKeyPair(serverPublicKey.p, serverPublicKey.g);
		byte[] dhSecret = DHUtils.dhSecret(clientKeyPair.getPrivateKey(), serverPublicKey.getPublicKey());
		byte[] httPakeKey = Utils.deriveKey(passwordTransform.apply(new String(credentialInput.getPassword())), dhSecret);
		
		BigInteger previousResponseId = subjectConfirmation.getRequestOrResponseId();
		sendPublicKeyAndContinueAuth(uri, httPakeKey, sessionId, previousResponseId, clientKeyPair.getPublicKey());
	}
	
	private void sendPublicKeyAndContinueAuth(URI uri, byte[] httPakeKey, String sessionId, BigInteger previousResponseId, BCDHPublicKey clientPublicKey) throws IOException
	{
		BigInteger nextRequestId = previousResponseId.add(BigInteger.ONE);
		HttpHead request3 = new HttpHead(uri);
		request3.setHeader(Headers.AUTHORIZATION, Constants.SCHEME);
		request3.setHeader(Headers.PUBLIC_KEY, Utils.encodeBase64(clientPublicKey.getY()));
		SubjectConfirmation clientConf = SubjectConfirmation.newInstance(nextRequestId, sessionId, Utils.generateNonce());
		request3.setHeader(Headers.SUBJECT_CONFIRMATION, clientConf.getHeaderValue());
		request3.setHeader(Headers.SIGNATURE, clientConf.getClientSignature(httPakeKey));
		AuthenticatedInfo newAuthInfo = new AuthenticatedInfo(sessionId, nextRequestId, previousResponseId, httPakeKey);
		authInfoRef.set(newAuthInfo);
		
		try(CloseableHttpResponse response3 = client.execute(request3))
		{
			int status = response3.getStatusLine().getStatusCode();
			if(status == HttpStatus.SC_UNAUTHORIZED)
			{
				throw new HttPakeException("Authentication failed.");
			}
			validateServerSignature(response3, newAuthInfo);
		}
	}
	
	private void validateServerSignature(CloseableHttpResponse response, AuthenticatedInfo authInfo)
	{
		SubjectConfirmation serverConf = SubjectConfirmation.newInstance(getHeader(response, Headers.SUBJECT_CONFIRMATION));
		String serverSignature = getHeader(response, Headers.SIGNATURE);
		if(!serverSignature.equals(serverConf.serverSignature(authInfo.getHttPakeKey(), response.getStatusLine().getStatusCode())))
		{
			throw new HttPakeException("Could not validate HttPake signature.");
		}
		authInfo.validateResponseId(serverConf.getRequestOrResponseId());
	}
	
	private Function<String,byte[]> getTransformFromName(String transformName) throws HttPakeException
	{
		switch(transformName.toLowerCase())
		{
		case Constants.TRANSFORM_IDENTITY:
			return Utils::getUtf8Bytes;
		case Constants.TRANSFORM_SHA256:
			return s-> Utils.getSha256Digest(Utils.getUtf8Bytes(s));
		default:
			throw new HttPakeException("Unknown password transform "+transformName);
		}
	}

	/**
	 * @return the AuthenticatedInfo
	 */
	//@UsedBy("tests")
	public AuthenticatedInfo getAuthenticatedInfo()
	{
		return authInfoRef.get();
	}
	
	/**
	 * Sets the auth info.
	 * @param info the info to set
	 */
	//@UsedBy("tests")
	public void setAuthInfo(AuthenticatedInfo info)
	{
		authInfoRef.set(info);
	}
	
	/**
	 * Stores authenticated information.
	 */
	public static class AuthenticatedInfo
	{
		private final String sessionId;
		private final AtomicReference<BigInteger> previousRequestId;
		private final String clientNonce;
		private final byte[] httPakeKey;
		private IdStore idStore;
		
		AuthenticatedInfo(String sessionId, BigInteger previousRequestId, BigInteger previousResponseId, byte[] httPakeKey)
		{
			this.sessionId = sessionId;
			this.previousRequestId = new AtomicReference<>(previousRequestId);
			this.clientNonce = Utils.generateNonce();
			this.httPakeKey = httPakeKey;
			this.idStore = new IdStore(Constants.REQUEST_ID_BUFFER_SIZE);
			this.idStore.checkIdAndRemember(previousResponseId);
		}
		
		/**
		 * Copy constructor.
		 * @param original the original.
		 */
		//@UsedBy("tests")
		public AuthenticatedInfo(AuthenticatedInfo original)
		{
			this.sessionId = original.sessionId;
			this.previousRequestId = new AtomicReference<BigInteger>(original.previousRequestId.get());
			this.clientNonce = original.clientNonce;
			this.httPakeKey = original.httPakeKey;
			this.idStore = new IdStore(original.idStore);
		}
		
		public void validateResponseId(BigInteger responseId)
		{
			idStore.checkIdAndRemember(responseId);
		}
		
		public String getSessionId()
		{
			return sessionId;
		}
		
		byte[] getHttPakeKey()
		{
			return httPakeKey;
		}
		
		
		String getClietNonce()
		{
			return clientNonce;
		}
		
		/**
		 * Returns the stored (previously used) request ID.
		 * @return the request ID
		 */
		// @UsedBy("tests")
		public BigInteger getRequestId()
		{
			return previousRequestId.get();
		}
		
		/**
		 * Gets the request ID to use next (this method is not idempotent).
		 * @return the request ID to use next
		 */
		BigInteger generateAndGetNextRequestId()
		{
			BigInteger result;
			BigInteger previous;
			do
			{
				previous = previousRequestId.get();
				result = previous.add(BigInteger.ONE);
			}
			while(!previousRequestId.compareAndSet(previous, result));
			return result;
		}
	}

}
