package ogs.switchon.common.communication.http;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import ogs.switchon.common.communication.http.constants.HTTPConstants;
import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.communication.http.utils.HttpConnectionHandler;
import ogs.switchon.common.exceptions.InvalidBufferStream;
import ogs.switchon.common.exceptions.SocketClosedException;
import ogs.switchon.common.logger.Logger;
import ogs.switchon.common.modules.communication.BaseTransactionBlockingQueue;
import ogs.switchon.common.modules.communication.MessageBean;
import ogs.switchon.common.modules.security.SslHelper;
import ogs.switchon.common.shared.ApplicationData;
import ogs.switchon.common.shared.CommonAppConstants;
import ogs.switchon.common.utilities.ApplicationUtils;

/**
 * This bean class is derived class of URL connection and it will holds the
 * single URL information. The basic operations handled in this method are: -
 * openConnection() - This method will create a connection and holds the input
 * and output streams.
 */

@SuppressWarnings("serial")
public class ConnectionHandler extends HttpConnectionHandler {

	/**
	 * Class name for the log
	 */
	private static final String CLASSNAME = ApplicationUtils.formatClassName("URL");
	/**
	 * HTTP/HTTPS Token cache hash map
	 */
	public static ConcurrentMap<String, Object> authTokenData = new ConcurrentHashMap<>();
	/**
	 * Connection properties bean
	 */
	private final ConnectionBean connectionBean;
	/**
	 * Token generated time
	 */
	private Long tokenGenerateTime;
	/**
	 * Token expiry period
	 */
	private final int tokenExpirePeriod;
	/**
	 * Auth type
	 */
	private final int authType;
	/**
	 * Character encoder
	 */
	private final CharsetEncoder encoder = Charset.forName("UTF-8").newEncoder();
	/**
	 * HTTP Method type
	 */
	private final MethodType methodType;

	/**
	 * HTTP Protocol type
	 */
	private transient ProtocolType protocolType;
	/**
	 * Response time out in seconds
	 */
	private final int responseTimeOut;
	/**
	 * Connection time out in seconds
	 */
	private final int connectionTimeOut;
	/**
	 * Used in full url method
	 */
	private static Integer connection_TimeOut = 10_000;
	/**
	 * used in full url method
	 */
//	private static Integer response_TimeOut = 30_000;
	/**
	 * Queue object
	 */
	private final BaseTransactionBlockingQueue queue;
	/**
	 * HTTP Constant
	 */
	private static final String HTTP_CONST = "http:";
	/**
	 * Return object
	 */
	private final Object retObject;
	/**
	 * Skip Certificate verification value
	 */
	private final boolean skipCertVerify;
	/**
	 * Token services bean
	 */
	private TokenBean tokenServicesBean;
	/**
	 * isStatusCodeRequired
	 */
	private boolean isStatusCodeRequired = false;
	/**
	 * Bearer token string appending
	 */
	private static final String BEARER_TAG = "Bearer ";
	/**
	 * ObjectMapper
	 */
	private final static ObjectMapper OBJ_MAPPER = new ObjectMapper();

	/**
	 * The constructor to used for creating connection with all parameter
	 *
	 * @param domainName            URL Domain name either IPAddress and Port or API
	 *                              URL
	 * @param contentType           Message Content Type for both Read/Write
	 *                              function
	 * @param methodType            Which method category to use this URL
	 * @param protocolType          Identify the URL protocol type either HTTP or
	 *                              HTTPS
	 * @param aliasName             SSL certificate alias name
	 * @param keyStorePassword      SSL key store encoded password
	 * @param keyStoreFileName      SSL key store file name
	 * @param appName               Application name
	 * @param versionNo             Application version number.
	 * @param services              API services path definition with Version no
	 * @param responseTimeOut       Response Time out seconds
	 * @param connectionTimeOut     Connection time out in seconds
	 * @param username              If the basic auth type means username is
	 *                              mandatory
	 * @param password              If the basic auth type means password is
	 *                              mandatory
	 * @param logId                 Logger Id
	 * @param logToken              Logger Token
	 * @param tokenServices         Token service path definition
	 * @param authType              HTTP Authentication category type 0 as NoAuth, 1
	 *                              as Token validation, 2 as username and password
	 * @param lastTokenGenerateTime Last Token Generated Time in milliseconds.
	 * @param expiryTime            Token Expire time interval in seconds.
	 * @param customeHeader         custom header of the api call
	 */
	public ConnectionHandler(final String domainName, final String contentType, final Integer methodType,
							 final boolean protocolType, final String aliasName, final String keyStorePassword,
							 final String keyStoreFileName, final String appName, final String versionNo, final String services,
							 final Integer responseTimeOut, final Integer connectionTimeOut, final String username,
							 final String password, final String logId, final String logToken, final String tokenServices,
							 final Integer authType, final Long lastTokenGenerateTime, final Integer expiryTime,
							 final String customeHeader, final BaseTransactionBlockingQueue queue, final Object retObject,
							 final boolean skipCertVerify) {
		super();
		if (aliasName == null)
			disableSslVerification();
		connectionBean = new ConnectionBean(domainName, contentType, logId, logToken, appName, versionNo, tokenServices,
				services, username, password, customeHeader, aliasName, keyStorePassword, keyStoreFileName);
		this.methodType = MethodType.getMethodType(methodType);
		this.protocolType = ProtocolType.geProtocolType(protocolType);
		this.responseTimeOut = responseTimeOut * 1000;
		this.connectionTimeOut = connectionTimeOut * 1000;
		this.tokenExpirePeriod = expiryTime;
		this.tokenGenerateTime = lastTokenGenerateTime;
		this.authType = authType;
		this.queue = queue;
		this.retObject = retObject;
		this.skipCertVerify = skipCertVerify;
	}

	/**
	 * @param domainName
	 * @param contentType
	 * @param methodType
	 * @param protocolType
	 * @param aliasName
	 * @param keyStorePassword
	 * @param keyStoreFileName
	 * @param appName
	 * @param versionNo
	 * @param services
	 * @param responseTimeOut
	 * @param connectionTimeOut
	 * @param username
	 * @param password
	 * @param additionalUrlParams
	 * @param logId
	 * @param logToken
	 * @param tokenServices
	 * @param authType
	 * @param lastTokenGenerateTime
	 * @param expiryTime
	 * @param customeHeader
	 * @param queue
	 * @param retObject
	 * @param skipCertVerify
	 */
	public ConnectionHandler(final String domainName, final String contentType, final Integer methodType,
							 final boolean protocolType, final String aliasName, final String keyStorePassword,
							 final String keyStoreFileName, final String appName, final String versionNo, final String services,
							 final Integer responseTimeOut, final Integer connectionTimeOut, final String username,
							 final String password, final String additionalUrlParams, final String logId, final String logToken,
							 final String tokenServices, final Integer authType, final Long lastTokenGenerateTime,
							 final Integer expiryTime, final String customeHeader, final BaseTransactionBlockingQueue queue,
							 final Object retObject, final boolean skipCertVerify) {
		super();
		if (aliasName == null)
			disableSslVerification();
		connectionBean = new ConnectionBean(domainName, contentType, logId, logToken, appName, versionNo, tokenServices,
				services, username, password, customeHeader, aliasName, keyStorePassword, keyStoreFileName,
				additionalUrlParams);
		this.methodType = MethodType.getMethodType(methodType);
		this.protocolType = ProtocolType.geProtocolType(protocolType);
		this.responseTimeOut = responseTimeOut * 1000;
		this.connectionTimeOut = connectionTimeOut * 1000;
		this.tokenExpirePeriod = expiryTime;
		this.tokenGenerateTime = lastTokenGenerateTime;
		this.authType = authType;
		this.queue = queue;
		this.retObject = retObject;
		this.skipCertVerify = skipCertVerify;
	}

	/**
	 * This method will create new connection of URL or API with respected
	 * domainName
	 *
	 * @param appData
	 *
	 * @throws IOException
	 */
	private URLConnection startConnect(final String logToken, final ApplicationData appData) throws IOException {
		logger.info(this.connectionBean.getLogId() + " Initiate URL Connection " + this.connectionBean.getDomainName(),
				CLASSNAME, logToken);
		String locUrlPath = null;
		String additionalUrlParams = this.connectionBean.getAdditionalUrlParams();
		final StringBuilder stringBuilder = new StringBuilder();
		if (this.connectionBean.getApplicationName() != null && !this.connectionBean.getApplicationName().isEmpty()) {
			stringBuilder.append(this.connectionBean.getApplicationName() + HTTPConstants.SEPARATOR.value());
		}
		if (this.connectionBean.getVersionNo() != null && !this.connectionBean.getVersionNo().isEmpty()) {
			stringBuilder.append(this.connectionBean.getVersionNo() + HTTPConstants.SEPARATOR.value());
		}
		if (this.connectionBean.getServicePath() != null && !this.connectionBean.getServicePath().isEmpty()) {
			stringBuilder.append(this.connectionBean.getServicePath());
		}
		if (additionalUrlParams != null) {
			additionalUrlParams = assignDefaultSwitchvariables(additionalUrlParams, appData);
			stringBuilder.append(additionalUrlParams);
		}
		locUrlPath = stringBuilder.toString();
		locUrlPath = replaceAppVariables(locUrlPath, appData);
		return openConnection(this.connectionBean.getDomainName(), protocolType, locUrlPath);
	}

	/**
	 * Construct url by replacing if app variables present for dynamic url
	 * constructions
	 *
	 * @param urlPath
	 * @param paramAppData
	 * @return
	 */
	public String replaceAppVariables(final String urlPath, final ApplicationData paramAppData) {
		String url = urlPath;
		final Pattern pattern = Pattern.compile("\\{([^\\\"]{0,4})\\}");
		final Matcher matcher = pattern.matcher(url);
		while (matcher.find()) {
			url = url.replace(matcher.group(),
					paramAppData.getFromNonSensitiveAppData(Integer.parseInt(matcher.group(1))));
		}
		return url;
	}

	/**
	 * @param defaultValues
	 * @param appData
	 */
	public String assignDefaultSwitchvariables(final String defaultValues, final ApplicationData appData) {
		String[] keyValuePairs = null;
		String[] pairs = null;
		String finalUrl = null;
		final StringBuffer additionalUrl = new StringBuffer();
		try {
			additionalUrl.append('?');
			keyValuePairs = defaultValues.split(",");
			for (final String pair : keyValuePairs) {
				pairs = pair.split("=");
				additionalUrl.append(pairs[0]).append('=')
						.append(appData.getFromNonSensitiveAppData(Integer.parseInt(pairs[1]))).append('&');
			}
			finalUrl = additionalUrl.substring(0, additionalUrl.length() - 1);
			keyValuePairs = null;
			pairs = null;
		} catch (ArrayIndexOutOfBoundsException | NumberFormatException e) {
			logger.error(this.connectionBean.getLogId() + "Exception in setDefaultSwitchvariables method", CLASSNAME,
					this.connectionBean.getLogToken());
		}
		return finalUrl;
	}

	/**
	 * This method will load common default parameter for http connection.
	 *
	 * @param tokenMessageBytes
	 * @param additionalTokenFields
	 * @throws IOException
	 */
	private HttpURLConnection initiateConnection(final URLConnection urlConnection, final String tokenMessageBytes,
												 final String additionalTokenFields) throws IOException {
		final HttpURLConnection httpUrlConnection = (HttpURLConnection) urlConnection;
		httpUrlConnection.setRequestMethod(methodType.getMethodType());

		httpUrlConnection.setReadTimeout(responseTimeOut);
		httpUrlConnection.setConnectTimeout(connectionTimeOut);
		if (this.connectionBean.getContentType() == null) {
			httpUrlConnection.setRequestProperty(HTTPConstants.CONTENT_TYPE.value(),
					HTTPConstants.DEFUALT_CHARSET.value());
		} else {
			httpUrlConnection.setRequestProperty(HTTPConstants.CONTENT_TYPE.value(),
					this.connectionBean.getContentType() + HTTPConstants.CHARSET.value());
			httpUrlConnection.setRequestProperty(HTTPConstants.ACCEPT.value(), this.connectionBean.getContentType());
		}
		httpUrlConnection.setDoOutput(true);
		httpUrlConnection.setDoInput(true);
		// @gt if the HTTP authentication type is Bearer Token means need to validate
		// token.
		setHttpHeader(httpUrlConnection, tokenMessageBytes, connectionBean.getLogId(), connectionBean.getLogToken(),
				additionalTokenFields);
		return httpUrlConnection;
	}

	/**
	 * This method will load common default parameter for https connection.
	 *
	 * @param tokenMessageBytes
	 * @param additionalTokenFields
	 * @throws IOException
	 */
	private HttpsURLConnection initiateSecureConnection(final URLConnection urlConnection, final String tokenMessageBytes,
														final String additionalTokenFields) throws IOException {
		final HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) urlConnection;
		httpsUrlConnection.setRequestMethod(methodType.getMethodType());
		httpsUrlConnection.setReadTimeout(responseTimeOut);
		httpsUrlConnection.setConnectTimeout(connectionTimeOut);
		if (StringUtils.hasText(this.connectionBean.getAliasName()))
			httpsUrlConnection.setSSLSocketFactory(SslHelper
					.loadSSLcertificate(this.connectionBean.getAliasName(), this.skipCertVerify).getSocketFactory());
		if (this.connectionBean.getContentType() == null) {
			httpsUrlConnection.setRequestProperty(HTTPConstants.CONTENT_TYPE.value(),
					HTTPConstants.DEFUALT_CHARSET.value());
		} else {
			httpsUrlConnection.setRequestProperty(HTTPConstants.CONTENT_TYPE.value(),
					this.connectionBean.getContentType() + HTTPConstants.CHARSET.value());
			httpsUrlConnection.setRequestProperty(HTTPConstants.ACCEPT.value(), this.connectionBean.getContentType());
		}
		httpsUrlConnection.setDoOutput(true);
		httpsUrlConnection.setDoInput(true);
		// @gt if the HTTP authentication type is Bearer Token means need to validate
		// token.
		setHttpsHeader(httpsUrlConnection, tokenMessageBytes, connectionBean.getLogId(), connectionBean.getLogToken(),
				additionalTokenFields);// Need
		return httpsUrlConnection;
	}

	@SuppressWarnings("unchecked")
	private void setHttpsHeader(final HttpsURLConnection httpConnection, final String tokenMessageBytes, final String msgId, final String logToken,
								final String additionalTokenFields) throws IOException {
		String token = null;
		if (this.connectionBean.getDomainName() != null) {
			token = (String) authTokenData.get(this.connectionBean.getDomainName());
			if (token != null)
				tokenGenerateTime = (Long) authTokenData.get(token);
			switch (authType) {
				case 1: // Token authentication
					if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
						token = super.generateToken(protocolType, this.connectionBean.getDomainName(),
								this.connectionBean.getApplicationName(),
								tokenServicesBean != null ? tokenServicesBean
										: this.connectionBean.getTokenServices() != null,
								this.connectionBean.getUsername(), this.connectionBean.getPassword(),
								this.connectionBean.getVersionNo(), this.methodType);

						authTokenData.put(this.connectionBean.getDomainName(), token);
						this.tokenGenerateTime = System.currentTimeMillis();
						httpConnection.addRequestProperty(HTTPConstants.AUTHORIZATION.value(), token);
					} else
						httpConnection.addRequestProperty(HTTPConstants.AUTHORIZATION.value(), token);
					break;
				case 2: // Basic authentication
					httpConnection.addRequestProperty(HTTPConstants.USERNAME.value(), this.connectionBean.getUsername());
					httpConnection.addRequestProperty(HTTPConstants.PASSWORD.value(), this.connectionBean.getPassword());
					break;
				case 3: // Custom headers
					final Base64.Decoder decoder = Base64.getDecoder();
					final ObjectMapper objectMapper = new ObjectMapper();
					final String customHeader = new String(decoder.decode(this.connectionBean.getCustomeHeader()),
							StandardCharsets.UTF_8);
					final Map<String, String> map = objectMapper.readValue(customHeader, Map.class);
					for (final Map.Entry<String, String> header : map.entrySet()) {
						httpConnection.addRequestProperty(header.getKey(), header.getValue());
					}
					break;
				case 4:
					if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
						token = super.generateOauthToken(protocolType, this.connectionBean.getDomainName(),
								this.connectionBean.getApplicationName() != null
										&& this.connectionBean.getApplicationName().trim().length() > 0
										? this.connectionBean.getApplicationName() + HTTPConstants.SEPARATOR.value()
										: "",
								tokenServicesBean != null ? tokenServicesBean : this.connectionBean.getTokenServices(),
								this.connectionBean.getUsername(), this.connectionBean.getPassword(),
								this.connectionBean.getVersionNo(), this.methodType, tokenMessageBytes, msgId, logToken,
								connectionBean.getAliasName(), skipCertVerify);

						authTokenData.put(this.connectionBean.getDomainName(), token);
						this.tokenGenerateTime = System.currentTimeMillis();
						authTokenData.put(token, tokenGenerateTime);
						httpConnection.setRequestProperty(HTTPConstants.AUTHORIZATION.value(), BEARER_TAG + token);
					} else
						httpConnection.setRequestProperty(HTTPConstants.AUTHORIZATION.value(), BEARER_TAG + token);
					if (additionalTokenFields != null) {
						logger.info(msgId + " AdditionalToken fields : " + additionalTokenFields, CLASSNAME, logToken);
						HashMap<String, String> headersParams;
						headersParams = (HashMap<String, String>) OBJ_MAPPER.readValue(additionalTokenFields, Map.class);
						headersParams.entrySet().stream()
								.forEach(entry -> httpConnection.addRequestProperty(entry.getKey(), entry.getValue()));
					}
					logger.info(msgId + " After token headers setted : ", CLASSNAME, logToken);
					break;
				case 5: // Original Basic authentication
					final String credentials = this.connectionBean.getUsername() + ":" + this.connectionBean.getPassword();
					final String authValue = Base64.getEncoder().encodeToString(credentials.getBytes());
					httpConnection.addRequestProperty(HTTPConstants.AUTHORIZATION.value(), "Basic " + authValue);
					break;
				default: // No authentication
					break;

			}
		}
	}

	@SuppressWarnings("unchecked")
	private void setHttpHeader(final HttpURLConnection httpConnection, final String tokenMessageBytes, final String msgId,
							   final String logToken, final String additionalTokenFields) throws IOException {
		String token = null;
		if (this.connectionBean.getDomainName() != null) {
			token = (String) authTokenData.get(this.connectionBean.getDomainName());
			if (token != null)
				tokenGenerateTime = (Long) authTokenData.get(token);
			switch (authType) {
				case 1: // Token authentication
					if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
						token = super.generateToken(protocolType, this.connectionBean.getDomainName(),
								this.connectionBean.getApplicationName(),
								tokenServicesBean != null ? tokenServicesBean
										: this.connectionBean.getTokenServices() != null,
								this.connectionBean.getUsername(), this.connectionBean.getPassword(),
								this.connectionBean.getVersionNo(), this.methodType);

						authTokenData.put(this.connectionBean.getDomainName(), token);
						this.tokenGenerateTime = System.currentTimeMillis();
						httpConnection.addRequestProperty(HTTPConstants.AUTHORIZATION.value(), token);
					} else
						httpConnection.addRequestProperty(HTTPConstants.AUTHORIZATION.value(), token);
					break;
				case 2: // Basic authentication
					httpConnection.addRequestProperty(HTTPConstants.USERNAME.value(), this.connectionBean.getUsername());
					httpConnection.addRequestProperty(HTTPConstants.PASSWORD.value(), this.connectionBean.getPassword());
					break;
				case 3: // Custom headers
					final Base64.Decoder decoder = Base64.getDecoder();
					final ObjectMapper objectMapper = new ObjectMapper();
					final String customHeader = new String(decoder.decode(this.connectionBean.getCustomeHeader()),
							StandardCharsets.UTF_8);
					final Map<String, String> map = objectMapper.readValue(customHeader, Map.class);
					for (final Map.Entry<String, String> header : map.entrySet()) {
						httpConnection.addRequestProperty(header.getKey(), header.getValue());
					}
					break;
				case 4:
					if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
						token = super.generateOauthToken(protocolType, this.connectionBean.getDomainName(),
								this.connectionBean.getApplicationName() != null
										&& this.connectionBean.getApplicationName().trim().length() > 0
										? this.connectionBean.getApplicationName() + HTTPConstants.SEPARATOR.value()
										: "",
								tokenServicesBean != null ? tokenServicesBean : this.connectionBean.getTokenServices(),
								this.connectionBean.getUsername(), this.connectionBean.getPassword(),
								this.connectionBean.getVersionNo(), this.methodType, tokenMessageBytes, msgId, logToken,
								connectionBean.getAliasName(), skipCertVerify);

						authTokenData.put(this.connectionBean.getDomainName(), token);
						this.tokenGenerateTime = System.currentTimeMillis();
						authTokenData.put(token, tokenGenerateTime);
						httpConnection.setRequestProperty(HTTPConstants.AUTHORIZATION.value(), BEARER_TAG + token);
						logger.info(msgId + " Authorization : " + BEARER_TAG + token, CLASSNAME, logToken);

					} else
						httpConnection.setRequestProperty(HTTPConstants.AUTHORIZATION.value(), BEARER_TAG + token);
					if (additionalTokenFields != null) {
						logger.info(msgId + " AdditionalToken fields : " + additionalTokenFields, CLASSNAME, logToken);
						HashMap<String, String> headersParams;
						headersParams = (HashMap<String, String>) OBJ_MAPPER.readValue(additionalTokenFields, Map.class);
						headersParams.entrySet().stream()
								.forEach(entry -> httpConnection.addRequestProperty(entry.getKey(), entry.getValue()));
					}
					logger.info(msgId + " After token headers setted : ", CLASSNAME, logToken);
					break;
				case 5: // Original Basic authentication
					final String credentials = this.connectionBean.getUsername() + ":" + this.connectionBean.getPassword();
					final String authValue = Base64.getEncoder().encodeToString(credentials.getBytes());
					httpConnection.addRequestProperty(HTTPConstants.AUTHORIZATION.value(), "Basic " + authValue);
					break;
				default: // No authentication
					break;
			}
		}
	}

	/**
	 * @param dataBytes Request message bytes
	 * @param token     If the token validation is enable means it should be need
	 * @return RecevicedBytes Response message bytes
	 * @throws InvalidBufferStream   Error in message bytes <code>dataBytes</code>
	 * @throws IOException           Socket and read/write error
	 * @throws SocketClosedException
	 */
	public byte[] doRequest(final String logToken, final byte[] dataBytes, final String token, final ApplicationData appData,
							final Object additionalFields) throws InvalidBufferStream, IOException, SocketClosedException {
		final URLConnection connection = startConnect(logToken, appData);
		logger.info(this.connectionBean.getLogId() + " URL for Connecting " + connection.getURL().toString(), CLASSNAME,
				logToken);
		byte[] responseBytes;
		if (protocolType == ProtocolType.HTTPS) {
			responseBytes = doHttpsRequest(logToken, dataBytes, token,
					initiateSecureConnection(connection, (String) additionalFields, null));
		} else {
			responseBytes = doHttpRequest(logToken, dataBytes, token, initiateConnection(connection, (String) additionalFields, null));
		}
		responseQueueProcess(responseBytes);
		return responseBytes;
	}

	/**
	 * @param dataBytes Request message bytes
	 * @param token     If the token validation is enable means it should be need
	 * @return RecevicedBytes Response message bytes
	 * @throws InvalidBufferStream   Error in message bytes <code>dataBytes</code>
	 * @throws IOException           Socket and read/write error
	 * @throws SocketClosedException
	 */
	public byte[] doRequest(final byte[] dataBytes, final String token, final ApplicationData appData,
							final Object additionalFields, final Object additionalTokenFields)
			throws InvalidBufferStream, IOException, SocketClosedException {
		final URLConnection connection = startConnect(this.connectionBean.getLogToken(), appData);
		logger.info(this.connectionBean.getLogId() + " URL for Connecting " + connection.getURL().toString(), CLASSNAME,
				this.connectionBean.getLogToken());
		byte[] responseBytes;
		if (protocolType == ProtocolType.HTTPS) {
			responseBytes = doHttpsRequest(this.connectionBean.getLogToken(), dataBytes, token,
					initiateSecureConnection(connection, (String) additionalFields, (String) additionalTokenFields));
		} else {
			responseBytes = doHttpRequest(this.connectionBean.getLogToken(), dataBytes, token,
					initiateConnection(connection, (String) additionalFields, (String) additionalTokenFields));
		}
		responseQueueProcess(responseBytes);
		return responseBytes;
	}

	private byte[] doHttpRequest(final String logToken, final byte[] dataBytes, final String token, final HttpURLConnection httpUrlConnection)
			throws InvalidBufferStream, IOException, SocketClosedException {
		if (token != null && token.length() > 0)
			httpUrlConnection.setRequestProperty(HTTPConstants.AUTHORIZATION.value(), token);
		if ((dataBytes == null || dataBytes.length <= 0)
				&& !httpUrlConnection.getRequestMethod().equals(MethodType.GET.getMethodType())) {
			throw new InvalidBufferStream("Unable to write in stream. Invalid Buffer size or buffer is NULL");
		}
		try {
			httpUrlConnection.setDoOutput(true);
			httpUrlConnection.connect();
		} catch (IOException e) {
			throw new SocketClosedException("End point not available 404", e);
		}
		byte[] responseData = null;
		if (httpUrlConnection.getRequestMethod().equals(MethodType.GET.getMethodType())) {
			responseData = doRequest(null, httpUrlConnection, dataBytes, connectionBean.getLogId(),
					logToken, isStatusCodeRequired);
		} else {
			responseData = doRequest(new BufferedOutputStream(httpUrlConnection.getOutputStream()), httpUrlConnection,
					dataBytes, connectionBean.getLogId(), logToken, isStatusCodeRequired);
		}
		final String responseMessage = httpUrlConnection.getResponseMessage();
		final int responseCode = httpUrlConnection.getResponseCode();
		if (CommonAppConstants.isRawMsgDisplay && Logger.isDebug()) {
			logger.debug(
					this.connectionBean.getLogId() + " Response Message " + responseMessage + "from "
							+ this.connectionBean.getDomainName() + " ResponseCode :: " + responseCode,
					CLASSNAME, logToken);
		}

		encoder.reset();
		httpUrlConnection.disconnect();

		return responseData;
	}

	private byte[] doHttpsRequest(final String logToken, final byte[] dataBytes, final String token,
								  final HttpsURLConnection httpsUrlConnection)
			throws InvalidBufferStream, IOException, SocketClosedException {
		if (token != null && token.length() > 0)
			httpsUrlConnection.setRequestProperty(HTTPConstants.AUTHORIZATION.value(), token);
		if ((dataBytes == null || dataBytes.length <= 0)
				&& !httpsUrlConnection.getRequestMethod().equals(MethodType.GET.getMethodType())) {
			throw new InvalidBufferStream("Unable to write in stream. Invalid Buffer size or buffer is NULL");
		}
		try {
			httpsUrlConnection.connect();
			logger.info(this.connectionBean.getLogId() + " Https URL connection established !!! ", CLASSNAME, logToken);
		} catch (IOException e) {
			throw new SocketClosedException("End point not available 404", e);
		}
		byte[] responseData = null;
		if (httpsUrlConnection.getRequestMethod().equals(MethodType.GET.getMethodType())) {
			responseData = doRequest(null, httpsUrlConnection, dataBytes, connectionBean.getLogId(),
					logToken, isStatusCodeRequired);
		} else {
			responseData = super.doRequest(new BufferedOutputStream(httpsUrlConnection.getOutputStream()),
					httpsUrlConnection, dataBytes, connectionBean.getLogId(), logToken, isStatusCodeRequired);
		}

		String responseMessage = httpsUrlConnection.getResponseMessage();
		final int responseCode = httpsUrlConnection.getResponseCode();
		if (CommonAppConstants.isRawMsgDisplay && Logger.isDebug())
			logger.debug(
					this.connectionBean.getLogId() + " Response Message " + responseMessage + "from "
							+ this.connectionBean.getDomainName() + " ResponseCode :: " + responseCode,
					CLASSNAME, logToken);
		responseMessage = null;
		encoder.reset();
		httpsUrlConnection.disconnect();

		return responseData;
	}

	/**
	 * Push or hit the given url with the http insecured protocol
	 *
	 * @param messageBytes message to be send
	 * @param fullUrl      full HTTP Url
	 * @param method       type of URL to be hit
	 * @param headers      headers as map to be sent on
	 * @return response as bytes
	 * @throws MalformedURLException if URL is incorrect pr improper
	 * @throws IOException           IO error on read and write
	 * @throws SocketClosedException if socket closed idenfied on or before write
	 * @throws InvalidBufferStream   invalid buffers received from the externals
	 */
	public byte[] pushRequest(final byte[] messageBytes, final String fullUrl, final MethodType method,
							  final Map<String, String> headers)
			throws MalformedURLException, IOException, SocketClosedException, InvalidBufferStream {
		byte[] retBytes;
		if (fullUrl.startsWith("https"))
			retBytes = pushSecuredRequest(messageBytes, fullUrl, method, headers, null, null, null);
		else {
			final HttpURLConnection connection = (HttpURLConnection) new URL(fullUrl).openConnection();
			connection.setRequestMethod(method.getMethodType());
			retBytes = super.doRequest(loadHeader(connection, headers, method), connection, messageBytes,
					connectionBean.getLogId(), connectionBean.getLogToken(), isStatusCodeRequired);
		}
		return retBytes;
	}

	private BufferedOutputStream loadHeader(final HttpURLConnection connection, final Map<String, String> headers,
											final MethodType method) throws IOException {
		connection.setRequestProperty(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.DEFUALT_CHARSET.value());
		connection.setReadTimeout(responseTimeOut);
		connection.setConnectTimeout(connectionTimeOut);
		connection.setDoOutput(true);
		for (final Map.Entry<String, String> header : headers.entrySet())
			connection.setRequestProperty(header.getKey(), header.getValue());
		connection.connect();
		return method == MethodType.GET ? null : new BufferedOutputStream(connection.getOutputStream());
	}

	/**
	 * @deprecated since 1.0.5, will be removed after 1.0.7. Desc - key location
	 *             removed and managed applicaiton <br/>
	 *             Push or hit the given url with the secured protocol
	 *
	 * @param messageBytes message to be send
	 * @param fullUrl      full HTTP Url
	 * @param method       type of URL to be hit
	 * @param headers      headers as map to be sent on
	 * @param keyAlias     if alias name of the certificate is available
	 * @param keySecret    key's secret
	 * @param keyStorePath key store path
	 * @return response as bytes
	 * @throws MalformedURLException if URL is incorrect pr improper
	 * @throws IOException           IO error on read and write
	 * @throws SocketClosedException if socket closed idenfied on or before write
	 * @throws InvalidBufferStream   invalid buffers received from the externals
	 */
	@Deprecated(since = "", forRemoval = false)
	public byte[] pushSecuredRequest(final byte[] messageBytes, final String fullUrl, final MethodType method,
									 final Map<String, String> headers, final String keyAlias, final String keySecret, final String keyStorePath)
			throws MalformedURLException, IOException, SocketClosedException, InvalidBufferStream {
		byte[] retBytes;
		if (fullUrl.startsWith(HTTP_CONST))
			retBytes = pushRequest(messageBytes, fullUrl, method, headers);
		else {
			final HttpsURLConnection connection = (HttpsURLConnection) new URL(fullUrl).openConnection();
			connection.setRequestMethod(method.getMethodType());
			if (keyAlias == null || keySecret == null || keyStorePath == null)
				connection.setSSLSocketFactory((SSLSocketFactory) SSLSocketFactory.getDefault());
			else
				connection.setSSLSocketFactory(
						SslHelper.loadSSLcertificate(keyAlias, this.skipCertVerify).getSocketFactory());
			retBytes = super.doRequest(loadHeader(connection, headers, method), connection, messageBytes,
					connectionBean.getLogId(), connectionBean.getLogToken(), isStatusCodeRequired);
		}
		return retBytes;
	}

	/**
	 * Push or hit the given url with the secured protocol
	 *
	 * @param messageBytes    message to be send
	 * @param fullUrl         full HTTP Url
	 * @param method          type of URL to be hit
	 * @param headers         headers as map to be sent on
	 * @param keyAlias        if alias name of the certificate is available
	 * @param sslVerification ssl verification flag
	 * @return response as bytes
	 * @throws MalformedURLException if URL is incorrect pr improper
	 * @throws IOException           IO error on read and write
	 * @throws SocketClosedException if socket closed idenfied on or before write
	 * @throws InvalidBufferStream   invalid buffers received from the externals
	 */
	public byte[] pushSecuredRequest(final byte[] messageBytes, final String fullUrl, final MethodType method,
									 final Map<String, String> headers, final String keyAlias, final boolean sslVerification)
			throws IOException, SocketClosedException, InvalidBufferStream {
		byte[] retBytes;
		if (fullUrl.startsWith(HTTP_CONST))
			retBytes = pushRequest(messageBytes, fullUrl, method, headers);
		else {
			final HttpsURLConnection connection = (HttpsURLConnection) new URL(fullUrl).openConnection();
			connection.setRequestMethod(method.getMethodType());
			connection.setSSLSocketFactory(SslHelper.loadSSLcertificate(keyAlias, sslVerification).getSocketFactory());
			retBytes = super.doRequest(loadHeader(connection, headers, method), connection, messageBytes,
					connectionBean.getLogId(), connectionBean.getLogToken(), isStatusCodeRequired);
		}
		return retBytes;
	}

	/**
	 * Push or hit the given url with the http insecured protocol
	 *
	 * @param messageBytes    message to be send
	 * @param fullUrl         full HTTP Url
	 * @param method          type of URL to be hit
	 * @param responseTimeout response timeout value in secs
	 * @param headers         headers as map to be sent on
	 * @return response as bytes
	 * @throws MalformedURLException if URL is incorrect pr improper
	 * @throws IOException           IO error on read and write
	 * @throws SocketClosedException if socket closed idenfied on or before write
	 * @throws InvalidBufferStream   invalid buffers received from the externals
	 */
	public byte[] pushRequest(final byte[] messageBytes, final String fullUrl, final MethodType method,
							  final Integer responseTimeOut, final Map<String, String> headers)
			throws IOException, SocketClosedException, InvalidBufferStream {
		byte[] retBytes;
		if (fullUrl.startsWith("https"))
			retBytes = pushSecuredRequest(messageBytes, fullUrl, method, headers, null, this.skipCertVerify,
					responseTimeOut);
		else {
			final HttpURLConnection connection = (HttpURLConnection) new URL(fullUrl).openConnection();
			connection.setRequestMethod(method.getMethodType());
			retBytes = super.doRequest(loadHeader(connection, headers, responseTimeOut, method), connection,
					messageBytes, connectionBean.getLogId(), connectionBean.getLogToken(),isStatusCodeRequired);
		}
		return retBytes;
	}

	private BufferedOutputStream loadHeader(final HttpURLConnection connection, final Map<String, String> headers,
											final Integer responseTimeOut, final MethodType method) throws IOException {
		connection.setRequestProperty(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.DEFUALT_CHARSET.value());
		connection.setReadTimeout(responseTimeOut * 1000);
		connection.setConnectTimeout(connection_TimeOut);
		connection.setDoOutput(true);
		for (final Map.Entry<String, String> header : headers.entrySet())
			connection.setRequestProperty(header.getKey(), header.getValue());
		connection.connect();
		return method == MethodType.GET ? null : new BufferedOutputStream(connection.getOutputStream());
	}

	private BufferedOutputStream loadCustomHeader(final HttpURLConnection connection, final Map<String, String> headers,
												  final Integer responseTimeOut, final MethodType method) throws IOException {
		connection.setReadTimeout(responseTimeOut * 1000);
		connection.setConnectTimeout(connection_TimeOut);
		connection.setDoOutput(true);
		for (final Map.Entry<String, String> header : headers.entrySet())
			connection.setRequestProperty(header.getKey(), header.getValue());
		connection.connect();
		return method == MethodType.GET ? null : new BufferedOutputStream(connection.getOutputStream());
	}

	/**
	 * @deprecated since 1.0.5, will be removed after 1.0.7. Desc - key location
	 *             removed and managed applicaiton <br/>
	 *             Push or hit the given url with the secured protocol
	 *
	 * @param messageBytes    message to be send
	 * @param fullUrl         full HTTP Url
	 * @param method          type of URL to be hit
	 * @param headers         headers as map to be sent on
	 * @param keyAlias        if alias name of the certificate is available
	 * @param keySecret       key's secret
	 * @param keyStorePath    key store path
	 * @param responseTimeOut Response timeout in secs
	 * @return response as bytes
	 * @throws MalformedURLException if URL is incorrect pr improper
	 * @throws IOException           IO error on read and write
	 * @throws SocketClosedException if socket closed idenfied on or before write
	 * @throws InvalidBufferStream   invalid buffers received from the externals
	 */
	@Deprecated(since = "", forRemoval = false)
	public byte[] pushSecuredRequest(final byte[] messageBytes, final String fullUrl, final MethodType method,
									 final Map<String, String> headers, final String keyAlias, final String keySecret, final String keyStorePath,
									 final Integer responseTimeOut)
			throws IOException, SocketClosedException, InvalidBufferStream {
		byte[] retBytes;
		if (fullUrl.startsWith(HTTP_CONST))
			retBytes = pushRequest(messageBytes, fullUrl, method, responseTimeOut, headers);
		else {
			final HttpsURLConnection connection = (HttpsURLConnection) new URL(fullUrl).openConnection();
			connection.setRequestMethod(method.getMethodType());
			if (keyAlias == null || keySecret == null || keyStorePath == null)
				connection.setSSLSocketFactory((SSLSocketFactory) SSLSocketFactory.getDefault());
			else
				connection.setSSLSocketFactory(
						SslHelper.loadSSLcertificate(keyAlias, this.skipCertVerify).getSocketFactory());
			retBytes = super.doRequest(loadHeader(connection, headers, responseTimeOut, method), connection,
					messageBytes, connectionBean.getLogId(), connectionBean.getLogToken(), isStatusCodeRequired);
		}
		return retBytes;
	}

	/**
	 *
	 * Push or hit the given url with the secured protocol
	 *
	 * @param messageBytes    message to be send
	 * @param fullUrl         full HTTP Url
	 * @param method          type of URL to be hit
	 * @param headers         headers as map to be sent on
	 * @param keyAlias        if alias name of the certificate is available
	 * @param sslVerfication  SSL Verification flag
	 * @param responseTimeOut Response timeout in secs
	 * @return response as bytes
	 * @throws MalformedURLException if URL is incorrect or improper
	 * @throws IOException           IO error on read and write
	 * @throws SocketClosedException if socket closed identified on or before write
	 * @throws InvalidBufferStream   invalid buffers received from the externals
	 */
	public byte[] pushSecuredRequest(final byte[] messageBytes, final String fullUrl, final MethodType method,
									 final Map<String, String> headers, final String keyAlias, final boolean sslVerfication,
									 final Integer responseTimeOut)
			throws IOException, SocketClosedException, InvalidBufferStream {
		byte[] retBytes;
		if (fullUrl.startsWith(HTTP_CONST))
			retBytes = pushRequest(messageBytes, fullUrl, method, responseTimeOut, headers);
		else {
			final HttpsURLConnection connection = (HttpsURLConnection) new URL(fullUrl).openConnection();
			connection.setRequestMethod(method.getMethodType());
			connection.setSSLSocketFactory(SslHelper.loadSSLcertificate(keyAlias, sslVerfication).getSocketFactory());
			retBytes = super.doRequest(loadHeader(connection, headers, responseTimeOut, method), connection,
					messageBytes, connectionBean.getLogId(), connectionBean.getLogToken(), isStatusCodeRequired);
		}
		return retBytes;
	}

	/**
	 *
	 * @param messageBytes
	 * @param fullUrl
	 * @param method
	 * @param headers
	 * @param keyAlias
	 * @param sslVerfication
	 * @param responseTimeOut
	 * @param isCustomHeader
	 * @return
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws SocketClosedException
	 * @throws InvalidBufferStream
	 */
	public byte[] pushSecuredRequest(final byte[] messageBytes, final String fullUrl, final MethodType method,
									 final Map<String, String> headers, final String keyAlias, final boolean sslVerfication,
									 final Integer responseTimeOut, final boolean isCustomHeader)
			throws MalformedURLException, IOException, SocketClosedException, InvalidBufferStream {
		byte[] retBytes;
		if (fullUrl.startsWith(HTTP_CONST))
			retBytes = pushRequest(messageBytes, fullUrl, method, responseTimeOut, headers);
		else {
			final HttpsURLConnection connection = (HttpsURLConnection) new URL(fullUrl).openConnection();
			connection.setRequestMethod(method.getMethodType());
			connection.setSSLSocketFactory(SslHelper.loadSSLcertificate(keyAlias, sslVerfication).getSocketFactory());
			retBytes = super.doRequest(loadCustomHeader(connection, headers, responseTimeOut, method), connection,
					messageBytes, connectionBean.getLogId(), connectionBean.getLogToken(), isStatusCodeRequired);
		}
		return retBytes;
	}

	/**
	 * <p>
	 * Write the response message to internal Queue
	 * </p>
	 *
	 * @param responseBytes
	 */
	private void responseQueueProcess(final byte[] responseBytes) {
		if (this.queue != null) {
			final MessageBean messageBean = new MessageBean(this.connectionBean.getDomainName(), retObject,
					responseBytes);
			this.queue.accept(messageBean);
		}
	}

	/**
	 *
	 * @returnskipCertVerify
	 */
	public boolean isSkipCertVerify() {
		return skipCertVerify;
	}

	/**
	 * tokenServicesBean
	 *
	 * @return
	 */
	public TokenBean getTokenServicesBean() {
		return tokenServicesBean;
	}

	/**
	 * setTokenServicesBean
	 *
	 * @param tokenServicesBean
	 */
	public void setTokenServicesBean(final TokenBean tokenServicesBean) {
		this.tokenServicesBean = tokenServicesBean;
	}

	/**
	 *
	 * @param cusHeader
	 * @return
	 */
	public void generateCustomHeader(final String cusHeader) {
		connectionBean.setCustomeHeader(cusHeader);
	}

	/**
	 *
	 * @return
	 */
	public ConnectionBean getConnectionBean() {
		return connectionBean;
	}

	@SuppressWarnings({ "PMD.UseShortArrayInitializer", "PMD.ReturnEmptyArrayRatherThanNull",
			"PMD.UncommentedEmptyMethodBody", "PMD.MissingOverride", "PMD.EmptyCatchBlock" })
	static void disableSslVerification() {
		try {
			// Create a trust manager that does not validate certificate chains
			final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				/**
				 *
				 */
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}

				/**
				 *
				 */
				@Override
				public void checkClientTrusted(final java.security.cert.X509Certificate[] arg0, final String arg1)
						throws CertificateException {
				}

				/**
				 *
				 */
				@Override
				public void checkServerTrusted(final java.security.cert.X509Certificate[] arg0, final String arg1)
						throws CertificateException {
				}
			} };

			// Install the all-trusting trust manager
			final SSLContext sc = SSLContext.getInstance("TLSv1.2");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

			// Create all-trusting host name verifier
			final HostnameVerifier allHostsValid = new HostnameVerifier() {
				/**
				 *
				 */
				public boolean verify(final String hostname, final SSLSession session) {
					return true;
				}
			};

			// Install the all-trusting host verifier
			HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
		} catch (NoSuchAlgorithmException | KeyManagementException e) {

		}
	}

	/**
	 * @param isStatusCodeRequired the isStatusCodeRequired to set
	 */
	public void setStatusCodeRequired(final boolean isStatusCodeRequired) {
		this.isStatusCodeRequired = isStatusCodeRequired;
	}

	/**
	 * @return the protocolType
	 */
	public ProtocolType getProtocolType() {
		return protocolType;
	}

	/**
	 * @param protocolType the protocolType to set
	 */
	public void setProtocolType(ProtocolType protocolType) {
		this.protocolType = protocolType;
	}
}
