package ogs.switchon.common.communication.http;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URLConnection;

import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.exceptions.InvalidBufferStream;
import ogs.switchon.common.exceptions.SocketClosedException;

/**
 * 
 * @author Gowtham Aug 20, 2019
 *         ======================================================================================
 *         This Module contains Proprietary Information of OGS Paylab Pvt ltd.,
 *         and should be treated as Confidential. SwitchOn� is a registered
 *         trademarks of OGS Paylab Pvt Ltd.
 * 
 *         Copyright (C)2008-2011 OGS Paylab pvt ltd. All Rights Reserved
 * 
 *         This Is Unpublished Proprietary Source Code Of OGS Paylab Pvt Ltd.
 * 
 *         The copyright notice above does not evidence any actual or intended
 *         publication of such Source code.
 *         ======================================================================================
 *         Class Description :- This Interface will have the skeleton of the
 *         basic HTTP/HTTPS operations. Descriptions are commented in top of the
 *         method declaration.
 *         ======================================================================================
 *         MODIFICATION HISTORY
 *
 *         DeveloperName Purpose/Reason ModifiedDate
 *         ---------------------------------------------------------------------------------------
 */
public interface J_CommunicationHandler extends Serializable {

	/**
	 * Create the HTTP/HTTPS URL connection with specified domain name. This method
	 * only create url connection and return back.
	 * 
	 * Parameter :
	 * 
	 * @param domainName   It is entire url configure property, like it may be
	 *                     combination of IPAddress and Port or normal url look like
	 *                     a ogspay.com
	 * @param protocolType The Domain Protocol Type definition parameter.
	 * @param servicePath  URL service path specified here which is include if the
	 *                     version no is presented means.
	 * @return URLConnection created open url connection from domain name.
	 * @throws IOException MalformedURL or invalid url connection exception
	 */
	URLConnection openConnection(String domainName, ProtocolType protocolType, String servicePath) throws IOException;

	/**
	 * Method will use both write and read functionality. Parameter:
	 * 
	 * @param outputStream   output stream to write a message to connection.
	 * @param httpConnection To be used to read message from URL connection.
	 * @param dataBytes      message to outgoing message datas.
	 * @return Byte values of received message.
	 * @throws SocketClosedException  Connection failure
	 * @throws InvalidBufferStream    Read write error, invalid packets
	 * @throws SocketTimeoutException If response timed out
	 */
	byte[] doRequest(BufferedOutputStream outputStream, HttpURLConnection httpConnection, byte[] dataBytes,
			String logId, String logToken) throws SocketClosedException, InvalidBufferStream, SocketTimeoutException;

}
