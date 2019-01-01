package org.hpake.examples.servlet;

import java.io.IOException;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class HttPakeServletResponseWrapper extends HttpServletResponseWrapper
{
	
	private final BufferingServletOutputStream out;
	public HttPakeServletResponseWrapper(HttpServletResponse response) throws IOException 
	{
		super(response);
		out = new BufferingServletOutputStream(response.getOutputStream());
	}
	@Override
	public ServletOutputStream getOutputStream() throws IOException
	{
		return out;
	}

	/**
	 * Commits the response.
	 */
	public void commitRequest() throws IOException
	{
		out.copyToDestination();
	}
	
	

}
