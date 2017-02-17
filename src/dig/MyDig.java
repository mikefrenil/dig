package dig;

import java.io.IOException;
import java.net.UnknownHostException;

import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;


/*
HOST_NOT_FOUND 	3
SUCCESSFUL 	0
TRY_AGAIN 	2
TYPE_NOT_FOUND 	4
UNRECOVERABLE 	1
*/
public class MyDig {
	
	

	public static void main(String[] args) throws IOException {
		
		Resolve resolve = new Resolve();
		resolve.query("co.jp", Type.ANY);
		
	}

}
