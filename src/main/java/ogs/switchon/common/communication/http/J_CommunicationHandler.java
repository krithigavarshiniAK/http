package ogs.switchon.common.communication.http;

import ogs.switchon.common.communication.http.constants.ProtocolType;

import java.io.IOException;
import java.io.Serializable;
import java.net.http.HttpRequest;


public interface J_CommunicationHandler extends Serializable {

	/**
	 * Create the HTTP Client connection with specified domain name. This method
	 * only create httpclient connection and returns http response object.
	 *
	 * Parameter :
	 *
	 * @param domainName   It is entire url configure property, like it may be
	 *                     combination of IPAddress and Port or normal url look like
	 *                     ogspay.com
	 * @param protocolType The Domain Protocol Type definition parameter.
	 * @param servicePath  client service path specified here includes the
	 *                     version number if present.
	 * @return HttpClient creates connection from domain name.
	 * @throws IOException MalformedURL or invalid url connection exception
	 */
	HttpRequest.Builder OpenConnection(String domainName, ProtocolType protocolType, String servicePath) throws IOException, InterruptedException;

}
