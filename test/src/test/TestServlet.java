package test;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@SuppressWarnings("serial")
public class TestServlet extends HttpServlet
{
	
	static final Map<String,String> servletData = new ConcurrentHashMap<>();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		String path = req.getPathInfo();
		String data = servletData.get(path);
		if(data == null)
		{
			resp.setStatus(404);
		}
		else
		{
			try(ServletOutputStream out = resp.getOutputStream())
			{
				out.write(data.getBytes("UTF-8"));
			}
		}
	}
	

}
