package ogs.switchon.common.communication.http;

import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.exceptions.InvalidBufferStream;
import ogs.switchon.common.exceptions.SocketClosedException;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.SocketTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public interface J_ClientHandler extends Serializable {
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

    HttpResponse<String> OpenConnection(String domainName, ProtocolType protocolType, String servicePath) throws IOException, InterruptedException;

    /**
     * Method will use both write and read functionality. Parameter:
     *
     * @param outputStream   output stream to write a message to connection.
     * @param httpRequest To be used to read message from httpclient connection.
     * @param dataBytes      message to outgoing message datas.
     * @return Byte values of received message.
     * @throws SocketClosedException  Connection failure
     * @throws InvalidBufferStream    Read write error, invalid packets
     * @throws SocketTimeoutException If response timed out
     */
    byte[] doRequest(BufferedOutputStream outputStream, HttpRequest httpRequest, byte[] dataBytes,
                     String logId, String logToken) throws SocketClosedException, InvalidBufferStream, IOException, InterruptedException;
}
