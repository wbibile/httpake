package org.hpake.examples.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;

import com.google.common.io.ByteStreams;
import com.google.common.io.FileBackedOutputStream;

/**
 * A servlet output that buffers the response entity body 
 * @author Wiraj Bibile
 */
class BufferingServletOutputStream extends ServletOutputStream
{
	private static final int FILE_THRESHHOLD = 1048576; 
	private final AtomicBoolean isOpen= new AtomicBoolean(true);
	private final  FileBackedOutputStream buffer;
	private final ServletOutputStream destination;

	
	BufferingServletOutputStream(ServletOutputStream destination)
	{
		this.destination  = destination;
		buffer = new FileBackedOutputStream(FILE_THRESHHOLD);
	}

	@Override
	public boolean isReady()
	{
		return isOpen.get();
	}

	@Override
	public void setWriteListener(WriteListener writeListener)
	{
		// Do nothing
	}

	@Override
	public void write(int b) throws IOException 
	{
		buffer.write(b);
	}

	@Override
	public void write(byte[] b) throws IOException
	{
		buffer.write(b);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException 
	{
		buffer.write(b, off, len);
	}

	@Override
	public void flush() throws IOException 
	{
		buffer.flush();
	}

	@Override
	public void close() throws IOException 
	{
		if(isOpen.compareAndSet(true, false))
		{
			buffer.close();
		}
	}
	
	/**
	 * Copies the buffered data to the destination stream.
	 */
	void copyToDestination() throws IOException
	{
		if(isOpen.get())
		{
			close();
		}
		try(InputStream source = buffer.asByteSource().openBufferedStream())
		{
			ByteStreams.copy(source, destination);
		}
		finally
		{
			destination.flush();
			destination.close();
		}
	}

}
