package ogs.switchon.common.communication.http.utils;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.net.ssl.HttpsURLConnection;

import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ogs.switchon.common.communication.http.J_CommunicationHandler;
import ogs.switchon.common.communication.http.SslParamsBean;
import ogs.switchon.common.communication.http.TokenBean;
import ogs.switchon.common.communication.http.constants.HTTPConstants;
import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.communication.http.exception.TokenGenerationFailure;
import ogs.switchon.common.exceptions.InvalidBufferStream;
import ogs.switchon.common.exceptions.SocketClosedException;
import ogs.switchon.common.logger.Logger;
import ogs.switchon.common.modules.security.SslHelper;
import ogs.switchon.common.shared.CommonAppConstants;
import ogs.switchon.common.utilities.ByteUtils;

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
 *         Class Description :- This class was derived from the interface URL
 *         connection. Instantiation restricted. This will holds the functions
 *         for the basic URL operations such as : - openConnection() - will open
 *         a URL connection. - readBytes() - Will read the bytes from input
 *         stream, and trim the actual size and return - writeReadBytes() - Will
 *         write the entire bytes, which was passed in the parameter. and return
 *         back received response message.
 *         ======================================================================================
 *         MODIFICATION HISTORY
 *
 *         DeveloperName Purpose/Reason ModifiedDate
 *         ---------------------------------------------------------------------------------------
 */
@SuppressWarnings("serial")
public abstract class HttpConnectionHandler implements J_CommunicationHandler {
	/**
	 * Class name
	 */
	private static final String CLASSNAME = "HCHD";
	/**
	 * Logger object
	 */
	protected static Logger logger = Logger.getLogger();
	/**
	 * Maximum buffer size
	 */
	private static final int MAX_BUFFER_SIZE = 9216;
	/**
	 * Response Status Code
	 */
	private static final String STATUS_CODE = "http_status_code";
	
	/**
	 * Default response node key
	 */
	private static final String DEFAULT_RESPONSE_NODE = "defaultRespNode";
	/**
	 * ERROR_MSG
	 */
	private static final String ERROR_MSG = "Socket Connection closed or IO Exception.";

	@Override
	public URLConnection openConnection(final String domainName, final ProtocolType protocolType,
			final String servicePath) throws IOException {
		Objects.requireNonNull(domainName, "URL Domain name is NULL");
		final URL url = new URL(
				protocolType.getProtocol() + domainName + HTTPConstants.SEPARATOR.value() + servicePath);
		return url.openConnection();
	}

	@Override
	public byte[] doRequest(final BufferedOutputStream outputStream, final HttpURLConnection httpConnection,
			final byte[] msgDataBytes, final String logId, final String logToken)
			throws InvalidBufferStream, SocketClosedException {
		byte[] dataBytes = null;
		final ObjectMapper objectMapper = new ObjectMapper();
		try {

			logger.info(logId, "Connecting to : " + httpConnection.getURL(), CLASSNAME, logToken);
			dataBytes = writeAndRead(outputStream, httpConnection, msgDataBytes, logId, logToken, objectMapper);
			if (dataBytes != null && dataBytes.length > 0) {
				final ObjectNode defaultNode = responseByteConvert(logId, logToken, dataBytes, objectMapper);

				// Add status code to the default node
				defaultNode.put(STATUS_CODE, httpConnection.getResponseCode());
				dataBytes = objectMapper.writeValueAsBytes(defaultNode);
			} else
				throw new SocketClosedException("No response from end point::" + httpConnection.getResponseCode());
		} catch (IOException e) {
			throw new SocketClosedException(ERROR_MSG, e);
		}
		return dataBytes;
	}

	/**
	 * @param logId
	 * @param logToken
	 * @param dataBytes
	 * @param objectMapper
	 * @return
	 * @throws JsonProcessingException
	 * @throws JsonMappingException
	 */
	private ObjectNode responseByteConvert(final String logId, final String logToken, byte[] dataBytes,
			final ObjectMapper objectMapper) throws JsonProcessingException {
		logger.info(logId, "Read  bytes length:" + dataBytes.length, CLASSNAME, logToken);
		if (CommonAppConstants.isRawMsgDisplay && Logger.isDebug())
			logger.debug("Received response :" + ByteUtils.copyBytesAsString(dataBytes, 0), CLASSNAME, logToken);
		
		// Convert the JSON string to a JsonNode (generic node type)
		final JsonNode parentNode = objectMapper.readTree(new String(dataBytes));

		// Create a default JSON node
		ObjectNode defaultNode = objectMapper.createObjectNode();

		if (parentNode instanceof ArrayNode arrayNode) {
			// If the parent node is an array, add it to the default node as "defaultNode"
			defaultNode.set(DEFAULT_RESPONSE_NODE, arrayNode);
		} else {
			defaultNode = (ObjectNode) parentNode;
		}
		return defaultNode;
	}
	
	public byte[] doRequest(final BufferedOutputStream outputStream, final HttpURLConnection httpConnection,
			final byte[] msgDataBytes, final String logId, final String logToken, final boolean hasRequiredStatusCode)
					throws SocketClosedException {
		byte[] dataBytes = null;
		final ObjectMapper objectMapper = new ObjectMapper();
		try {

			logger.info(logId, "Connecting to : " + httpConnection.getURL(), CLASSNAME, logToken);
			dataBytes = writeAndRead(outputStream, httpConnection, msgDataBytes, logId, logToken, objectMapper);
			if (dataBytes != null && dataBytes.length > 0) {
				// Add status code to the default node
				if (hasRequiredStatusCode) {
					final ObjectNode defaultNode = responseByteConvert(logId, logToken, dataBytes, objectMapper);
					defaultNode.put(STATUS_CODE, httpConnection.getResponseCode());
					dataBytes = objectMapper.writeValueAsBytes(defaultNode);
				}
					
			} else
				throw new SocketClosedException("No response from end point::" + httpConnection.getResponseCode());
		} catch (IOException e) {
			throw new SocketClosedException(ERROR_MSG, e);
		}
		return dataBytes;
	}

	/**
	 * @param outputStream
	 * @param httpConnection
	 * @param msgDataBytes
	 * @param logId
	 * @param logToken
	 * @param objectMapper
	 * @return
	 * @throws IOException
	 * @throws JsonProcessingException
	 */
	private byte[] writeAndRead(final BufferedOutputStream outputStream, final HttpURLConnection httpConnection,
			final byte[] msgDataBytes, final String logId, final String logToken, final ObjectMapper objectMapper)
			throws IOException {
		byte[] dataBytes;
		if (!httpConnection.getRequestMethod().equals(MethodType.GET.getMethodType())) {
			Objects.requireNonNull(outputStream, "Output Stream is NULL");
			outputStream.write(msgDataBytes);
			outputStream.flush();
			outputStream.close();
			logger.info(logId, "Written bytes length:" + msgDataBytes.length, CLASSNAME, logToken);
			if (CommonAppConstants.isRawMsgDisplay && Logger.isDebug())
				logger.debug("written message :" + ByteUtils.copyBytesAsString(msgDataBytes, 0), CLASSNAME, logToken);
		}
		/* did not get any response body from the end point need to check */
		if (httpConnection.getResponseCode() == HttpURLConnection.HTTP_ACCEPTED) {
			dataBytes = objectMapper.writeValueAsBytes(objectMapper.createObjectNode());
		} else if (httpConnection.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
			dataBytes = readBytes(httpConnection.getInputStream());
		}else {
			/* error from server */
			dataBytes = readBytes(httpConnection.getErrorStream());
		}
		return dataBytes;
	}

	/**
	 * Decrecated method for do request
	 * 
	 * @param outputStream
	 * @param httpConnection
	 * @param msgDataBytes
	 * @return
	 * @throws SocketClosedException
	 * @throws InvalidBufferStream
	 */
	@Deprecated(since = "", forRemoval = false)
	public byte[] doRequest(final BufferedOutputStream outputStream, final HttpURLConnection httpConnection,
			final byte[] msgDataBytes) throws SocketClosedException, InvalidBufferStream {
		byte[] dataBytes = null;
		Objects.requireNonNull(outputStream, "Output Stream is NULL");
		try {
			if (!httpConnection.getRequestMethod().equals(MethodType.GET.getMethodType())) {
				outputStream.write(msgDataBytes);
				outputStream.flush();
				outputStream.close();
			}
			if (httpConnection.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
				dataBytes = readBytes(httpConnection.getInputStream());
			} else {
				/* error from server */
				dataBytes = readBytes(httpConnection.getErrorStream());
			}
		} catch (IOException e) {
			throw new SocketClosedException(ERROR_MSG, e);
		}
		return dataBytes;
	}

	/**
	 * This method will do a receive the message from the particular URL connection.
	 * 
	 * Parameter:
	 * 
	 * @param inputStream - To be used to read message from URL connection.
	 * @return Byte values of received message.
	 * @throws IOException in case of read/socket failure
	 */
	private byte[] readBytes(final InputStream inputStream) throws IOException {
		Objects.requireNonNull(inputStream, "InputStream value is NULL");
		int size = 0;
		byte[] retBytes = null;
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();) {
			final byte[] dataBytes = new byte[MAX_BUFFER_SIZE];
			do {
				size = inputStream.read(dataBytes);
				// End of stream check
				if (size == -1)
					break;
				else {
					bos.write(ByteUtils.copyBytesFromByteArray(dataBytes, 0, size));
				}
			} while (size > -1);
			inputStream.close();
			retBytes = bos.toByteArray();
		}
		return retBytes;
	}

	/**
	 * 
	 * <p>
	 * Generate token
	 * </p>
	 * 
	 * @param protocolType    HTTP/HTTPS
	 * @param domainName      host name
	 * @param applicationName app name
	 * @param tokenServices   token services
	 * @param username        user name for auth
	 * @param password        password for auth
	 * @param methodType2
	 * @return token
	 * @throws TokenGenerationFailure if failed
	 */
	@SuppressWarnings("unchecked")
	public String generateToken(final ProtocolType protocolType, final String baseUrlDomainName,
			final String baseUrlApplicationName, final Object tokenServices, final String authUsername,
			final String authPassword, final String baseUrlversionNo, final MethodType baseUrlmethodType)
			throws TokenGenerationFailure {
		String token = null;
		ObjectMapper mapper = null;
		int responseCode = 0;
		StringBuilder content = null;
		URLConnection connection;
		MethodType methodType;
		Map<String, String> tokenParams = null;
		try {
			if (tokenServices instanceof TokenBean tokenServicesBean) {
				connection = openConnection(tokenServicesBean.getDomainName(), protocolType,
						tokenServicesBean.getAppName() + HTTPConstants.SEPARATOR.value()
								+ tokenServicesBean.getVersionNo() + HTTPConstants.SEPARATOR.value()
								+ tokenServicesBean.getServicePath());
				tokenParams = new ObjectMapper().readValue(tokenServicesBean.getAdditionalTokenParams().getBytes(),
						Map.class);
				methodType = MethodType.getMethodType(tokenServicesBean.getMethodType());
			} else {
				connection = openConnection(baseUrlDomainName, protocolType,
						baseUrlApplicationName + HTTPConstants.SEPARATOR.value() + baseUrlversionNo
								+ HTTPConstants.SEPARATOR.value() + (String) tokenServices);
				methodType = baseUrlmethodType;
			}
			final HttpURLConnection urlConnection = (HttpURLConnection) connection;
			urlConnection.addRequestProperty(HTTPConstants.USERNAME.value(), authUsername);
			urlConnection.addRequestProperty(HTTPConstants.PASSWORD.value(), authPassword);
			for (final Map.Entry<String, String> header : tokenParams.entrySet())
				urlConnection.setRequestProperty(header.getKey(), header.getValue());
			urlConnection.addRequestProperty(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.DEFUALT_CHARSET.value());
			urlConnection.setRequestMethod(methodType.getMethodType());
			responseCode = urlConnection.getResponseCode();
			if (responseCode != HttpURLConnection.HTTP_OK) {
				token = "Failure";
			} else {
				try (BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));) {
					String line = in.readLine();
					content = new StringBuilder();
					while (line != null) {
						content.append(line);
						content.append(System.lineSeparator());
						line = in.readLine();
					}
				}
				token = content.toString();
				mapper = new ObjectMapper();
				final Map<String, String> response = mapper.readValue(token, Map.class);
				token = response.get("Token");
			}
		} catch (IOException ioe) {
			throw new TokenGenerationFailure("Unble to genearate the token", ioe);
		}
		return token;
	}

	/**
	 * 
	 * <p>
	 * Generate token
	 * </p>
	 * 
	 * @param protocolType          HTTP/HTTPS
	 * @param domainName            host name
	 * @param applicationName       app name
	 * @param tokenServices         token services
	 * @param username              user name for auth
	 * @param password              password for auth
	 * @param additionalTokenParams
	 * @param additionalTokenParams
	 * @param versionNo
	 * @param baseUrlmethodType
	 * @param tokenMessageBytes
	 * @param logToken
	 * @param msgId
	 * @return token
	 * @throws TokenGenerationFailure if failed
	 */
	@SuppressWarnings("unchecked")
	public String generateOauthToken(final ProtocolType protocolType, final String baseUrlDomainName,
			final String baseUrlApplicationName, final Object tokenServices, final String authUsername,
			final String authPassword, final String baseUrlversionNo, final MethodType baseUrlmethodType,
			final String tokenMessageBytes, final String msgId, final String logToken, final String keyAlias,
			final boolean skipCertVerify) throws TokenGenerationFailure {
		String token = null;
		final URLConnection connection;
		MethodType methodType = null;
		Map<String, String> tokenParams = new HashMap<>();
		final StringBuilder postData = new StringBuilder();
		final StringBuilder urlCompleteData = new StringBuilder();
		try {
			if (tokenServices instanceof TokenBean tokenServicesBean) {
				urlCompleteData.append(
						tokenServicesBean.getAppName() != null && tokenServicesBean.getAppName().trim().length() > 0
								? tokenServicesBean.getAppName() + HTTPConstants.SEPARATOR.value()
								: "");
				urlCompleteData.append(
						tokenServicesBean.getVersionNo() != null && tokenServicesBean.getVersionNo().trim().length() > 0
								? tokenServicesBean.getVersionNo() + HTTPConstants.SEPARATOR.value()
								: "");
				urlCompleteData.append(tokenServicesBean.getServicePath());
				connection = openConnection(tokenServicesBean.getDomainName(), protocolType,
						urlCompleteData.toString());
				try {
					if (tokenServicesBean.getAdditionalTokenParams() != null)
						tokenParams = new ObjectMapper()
								.readValue(tokenServicesBean.getAdditionalTokenParams().getBytes(), Map.class);
				} catch (IOException e) {
					logger.error(msgId + " Exception occured in this block for Json message for additional token params ", CLASSNAME, e);
// no need to throw failures   , it is been used as template name so it has been handled in this form - Manoj
				}
				methodType = MethodType.getMethodType(tokenServicesBean.getMethodType());
			} else {
				connection = openConnection(baseUrlDomainName, protocolType,
						baseUrlApplicationName + (String) tokenServices);
			}

			tokenParams.put("client_id", authUsername);
			tokenParams.put("client_secret", authPassword);
			byte[] reqMessageBytes = null;
			if (tokenMessageBytes == null) {
				for (final Map.Entry<String, String> param : tokenParams.entrySet()) {
					if (postData.length() != 0)
						postData.append('&');
					postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
					postData.append('=');
					postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
					reqMessageBytes = postData.toString().getBytes();
				}
			} else {
				reqMessageBytes = tokenMessageBytes.getBytes();
				methodType = MethodType.POST;
			}
			
			if (connection instanceof HttpsURLConnection) {
				final SslParamsBean httpsOperationParamsBean = new SslParamsBean(keyAlias, skipCertVerify,
						protocolType);
				token = doHttpsOperation(connection, msgId, logToken, httpsOperationParamsBean, methodType,
						reqMessageBytes);
			} else if (connection instanceof HttpURLConnection) {
				token = doHttpOperation(connection, msgId, logToken, methodType, reqMessageBytes);
			}
		} catch (IOException ioe) {
			throw new TokenGenerationFailure("Unable to generate the token " + ioe.getLocalizedMessage(), ioe);
		}
		return token;
	}
	
	/**
	 * <p>
	 * Performs the operations based on Https Connection
	 * </p>
	 * 
	 * 
	 * @param connection
	 * @param msgId
	 * @param logToken
	 * @param keyAlias
	 * @param skipCertVerify
	 * @param protocolType
	 * @param methodType
	 * @param reqMessageBytes
	 * @return
	 * @throws IOException
	 */
	private String doHttpsOperation(final URLConnection connection, final String msgId, final String logToken,
			final SslParamsBean sslParamsBean, final MethodType methodType, final byte[] reqMessageBytes)
			throws IOException {
		final HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) connection;
		if (sslParamsBean.getKeyAlias() != null && StringUtils.hasText(sslParamsBean.getKeyAlias())
				&& sslParamsBean.getProtocolType() == ProtocolType.HTTPS) {
			httpsUrlConnection.setSSLSocketFactory(
					SslHelper.loadSSLcertificate(sslParamsBean.getKeyAlias(), sslParamsBean.isSkipCertVerify())
							.getSocketFactory());
		}
		String contentType = HTTPConstants.URLENCODED.value();
		if (methodType != null) {
			httpsUrlConnection.setRequestMethod(methodType.getMethodType());
			contentType = HTTPConstants.DEFUALT_CHARSET.value();
		}
		logger.info(msgId + " Url request sent : " + connection.getURL().toString(),
				CLASSNAME, logToken);
		httpsUrlConnection.setRequestProperty(HTTPConstants.CONTENT_TYPE.value(), contentType);
		httpsUrlConnection.setDoOutput(true);
		if (Logger.isDebug())
			logger.debug(msgId + " Token request message " + ByteUtils.copyBytesAsString(reqMessageBytes, 0),
					CLASSNAME, logToken);
		httpsUrlConnection.getOutputStream().write(reqMessageBytes);
		int responseCode = 0;
		responseCode = httpsUrlConnection.getResponseCode();
		StringBuilder content = null;
		String token = null;
		if (responseCode != HttpURLConnection.HTTP_OK) {
			logger.info(msgId + " Auth token call response " + responseCode, CLASSNAME, logToken);
			throw new TokenGenerationFailure("Auth token getting failure : Response " + responseCode);
		} else {
			try (BufferedReader in = new BufferedReader(new InputStreamReader(httpsUrlConnection.getInputStream()))) {
				String line = in.readLine();
				content = new StringBuilder();
				while (line != null) {
					content.append(line);
					content.append(System.lineSeparator());
					line = in.readLine();
				}
			}
			token = getTokenValue(content.toString(), msgId, logToken);
			if (token == null) {
				logger.info(msgId + "Auth token response msg " + content, CLASSNAME, logToken);
				throw new TokenGenerationFailure("Auth token getting null token : Response " + content);
			} else {
				logger.info(msgId + "Auth token successfully received ", CLASSNAME, logToken);
			}
		}
		return token;
	}
	/**
	 * <p>
	 * Performs the operations based on Http Connection
	 * </p>
	 * 
	 * @param connection
	 * @param msgId
	 * @param logToken
	 * @param methodType
	 * @param reqMessageBytes
	 * @return
	 * @throws IOException
	 */
	private String doHttpOperation(final URLConnection connection, final String msgId, final String logToken,
			final MethodType methodType, final byte[] reqMessageBytes) throws IOException {
		String contentType = HTTPConstants.URLENCODED.value();
		final HttpURLConnection httpUrlConnection = (HttpURLConnection) connection;
		if (methodType != null) {
			httpUrlConnection.setRequestMethod(methodType.getMethodType());
			contentType = HTTPConstants.DEFUALT_CHARSET.value();
		}
		logger.info(msgId + " Url request sent : " + connection.getURL().toString(),
				CLASSNAME, logToken);
		httpUrlConnection.setRequestProperty(HTTPConstants.CONTENT_TYPE.value(), contentType);
		httpUrlConnection.setDoOutput(true);
		if (Logger.isDebug())
			logger.debug(msgId + "Token request message " + ByteUtils.copyBytesAsString(reqMessageBytes, 0),
					CLASSNAME, logToken);
		httpUrlConnection.getOutputStream().write(reqMessageBytes);
		int responseCode = 0;
		responseCode = httpUrlConnection.getResponseCode();
		String token = null;
		StringBuilder content = null;
		if (responseCode != HttpURLConnection.HTTP_OK) {
			logger.info(msgId + "Auth token call response " + responseCode, CLASSNAME, logToken);
			throw new TokenGenerationFailure("Auth token getting failure : Response " + responseCode);
		} else {
			try (BufferedReader in = new BufferedReader(new InputStreamReader(httpUrlConnection.getInputStream()))) {
				String line = in.readLine();
				content = new StringBuilder();
				while (line != null) {
					content.append(line);
					content.append(System.lineSeparator());
					line = in.readLine();
				}
			}
			token = getTokenValue(content.toString(), msgId, logToken);
			if (token == null) {
				logger.info(msgId + "Auth token response msg " + content, CLASSNAME, logToken);
				throw new TokenGenerationFailure("Auth token getting null token : Response " + content);
			} else {
				logger.info(msgId + "Auth token successfully received ", CLASSNAME, logToken);
			}
		}
		return token;
	}
	
		

	/**
	 * <p>
	 * Authorization token response message parsing based on the incoming response.
	 * Whether the Json message with signature or without signature.
	 * </p>
	 * 
	 * @param tokenResponse - Token message response received
	 * @param msgId         - Logger unique identifier
	 * @param logToken      - Logger access token
	 * @return access token
	 */
	@SuppressWarnings("unchecked")
	private static String getTokenValue(final String tokenResponse, final String msgId, final String logToken) {
		final ObjectMapper objectMapper = new ObjectMapper();
		String authToken = null;
		try {
			final Map<String, Object> json = objectMapper.readValue(tokenResponse, Map.class);
			if (json.containsKey("payload")) {
				final String decodedMessage = ByteUtils
						.copyBytesAsString(Base64.getDecoder().decode((String) json.get("payload")), 0);
				if (Logger.isDebug())
					logger.debug(msgId + "Token response decoded Value ! " + decodedMessage, CLASSNAME, logToken);
				final Map<String, String> clearResponse = objectMapper.readValue(decodedMessage, Map.class);
				if (clearResponse.containsKey("access_token")) {
					authToken = clearResponse.get("access_token");
					logger.info(msgId + " Received Authorization token is  ! : " + authToken , CLASSNAME, logToken);
				}
			}
			logger.info(msgId + "Authorization token received !", CLASSNAME, logToken);
		} catch (JsonProcessingException e) {
			logger.error(msgId + "Auth token response format not JSON signature", CLASSNAME, logToken);
			authToken = tokenResponse;
		}
		return authToken;
	}
}
