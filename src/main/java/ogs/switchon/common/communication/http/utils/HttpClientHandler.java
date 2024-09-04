package ogs.switchon.common.communication.http.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ogs.switchon.common.communication.http.J_ClientHandler;
import ogs.switchon.common.communication.http.SslParamsBean;
import ogs.switchon.common.communication.http.TokenBean;
import ogs.switchon.common.communication.http.constants.HTTPConstants;
import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.communication.http.exception.TokenGenerationFailure;
import ogs.switchon.common.exceptions.SocketClosedException;
import ogs.switchon.common.logger.Logger;
import ogs.switchon.common.modules.security.SslHelper;
import ogs.switchon.common.shared.CommonAppConstants;
import ogs.switchon.common.utilities.ByteUtils;
import org.springframework.util.StringUtils;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public abstract class HttpClientHandler implements J_ClientHandler {
    private HttpClient httpClient = null;
    private HttpRequest baseRequest;
    private static final String CLASSNAME = "HCHD";
    protected static Logger logger = Logger.getLogger();
    private static final String STATUS_CODE = "http_status_code";
    /**
     * Maximum buffer size
     */
    private static final int MAX_BUFFER_SIZE = 9216;
    /**
     * Default response node key
     */
    private static final String DEFAULT_RESPONSE_NODE = "defaultRespNode";
    /**
     * ERROR_MSG
     */
    private static final String ERROR_MSG = "Socket Connection closed or IO Exception.";
    public HttpClientHandler(final String domainName, final ProtocolType protocolType, final String servicePath) {
        this.httpClient = HttpClient.newHttpClient();

        Objects.requireNonNull(domainName, "URL Domain name is NULL");

        // Created a base HttpRequest that can be reused or extended
        final String url = protocolType.getProtocol() + domainName + HTTPConstants.SEPARATOR.value() + servicePath;
        this.baseRequest = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build();
    }

    public HttpClientHandler() {

    }

    @Override
    public HttpRequest OpenConnection(final String domainName, final ProtocolType protocolType, final String servicePath) throws IOException, InterruptedException {
        return httpClient.send(baseRequest, HttpResponse.BodyHandlers.ofString()).request();
    }

    @Override
    public byte[] doRequest(final BufferedOutputStream outputStream, final HttpRequest baseRequest,
                            final byte[] msgDataBytes, final String logId, final String logToken) throws IOException, InterruptedException, SocketClosedException {
        byte[] dataBytes = null;
        final ObjectMapper objectMapper = new ObjectMapper();
        HttpResponse<InputStream> response = null;
        try {
            HttpRequest modifiedRequest = HttpRequest.newBuilder(baseRequest.uri())
                    .method("POST", HttpRequest.BodyPublishers.ofByteArray(msgDataBytes))
                    .build();
            response = httpClient.send(modifiedRequest, HttpResponse.BodyHandlers.ofInputStream());
            logger.info(logId, "Connecting to : " + baseRequest.uri().getPath(), CLASSNAME, logToken);
            dataBytes = writeAndRead(outputStream, baseRequest, msgDataBytes, logId, logToken, objectMapper);
            if (dataBytes != null && dataBytes.length > 0) {
                final ObjectNode defaultNode = responseByteConvert(logId, logToken, dataBytes, objectMapper);

                defaultNode.put(STATUS_CODE, response.statusCode());
                dataBytes = objectMapper.writeValueAsBytes(defaultNode);
            } else
                throw new SocketClosedException("No response from end point::" + response.statusCode());
        } catch (IOException e) {
            throw new SocketClosedException(ERROR_MSG, e);
        }
        return dataBytes;
    }

    public byte[] doRequest(final BufferedOutputStream outputStream, final HttpRequest baseRequest,
                            final byte[] msgDataBytes, final String logId,
                            final String logToken, final boolean hasRequiredStatusCode)
            throws SocketClosedException, IOException, InterruptedException {
        byte[] dataBytes = null;
        final ObjectMapper objectMapper = new ObjectMapper();
        HttpResponse<InputStream> response = null;
        try {
            HttpRequest modifiedRequest = HttpRequest.newBuilder(baseRequest.uri())
                    .method("POST", HttpRequest.BodyPublishers.ofByteArray(msgDataBytes))
                    .build();
            response = httpClient.send(modifiedRequest, HttpResponse.BodyHandlers.ofInputStream());
            logger.info(logId, "Connecting to : " + baseRequest.uri().getPath(), CLASSNAME, logToken);
            dataBytes = writeAndRead(outputStream, baseRequest, msgDataBytes, logId, logToken, objectMapper);
            if (dataBytes != null && dataBytes.length > 0) {
                // Add status code to the default node
                if (hasRequiredStatusCode) {
                    final ObjectNode defaultNode = responseByteConvert(logId, logToken, dataBytes, objectMapper);
                    defaultNode.put(STATUS_CODE, response.statusCode());
                    dataBytes = objectMapper.writeValueAsBytes(defaultNode);
                } else
                    throw new SocketClosedException("No response from end point::" + response.statusCode());
            }
        } catch (IOException e) {
            throw new SocketClosedException(ERROR_MSG, e);
        }
        return dataBytes;
    }

    /**
     * @param outputStream
     * @param msgDataBytes
     * @param logId
     * @param logToken
     * @param objectMapper
     * @return
     * @throws IOException
     * @throws InterruptedException
     */
    private byte[] writeAndRead(final BufferedOutputStream outputStream, final HttpRequest baseRequest,
                                final byte[] msgDataBytes, final String logId, final String logToken,
                                final ObjectMapper objectMapper) throws IOException, InterruptedException {
        byte[] dataBytes;
        HttpResponse<InputStream> response = null;
        InputStream inputStream;

        if (!baseRequest.method().equalsIgnoreCase(MethodType.GET.getMethodType())) {
            Objects.requireNonNull(outputStream, "Output Stream is NULL");
            HttpRequest modifiedRequest = HttpRequest.newBuilder(baseRequest.uri())
                    .method("POST", HttpRequest.BodyPublishers.ofByteArray(msgDataBytes))
                    .build();
            response = httpClient.send(modifiedRequest, HttpResponse.BodyHandlers.ofInputStream());
            logger.info(logId, "Written bytes length:" + msgDataBytes.length, CLASSNAME, logToken);
            if (CommonAppConstants.isRawMsgDisplay && Logger.isDebug())
                logger.debug("written message :" + ByteUtils.copyBytesAsString(msgDataBytes, 0), CLASSNAME, logToken);
        }
        if (response.statusCode() == HttpURLConnection.HTTP_ACCEPTED) {
            dataBytes = objectMapper.writeValueAsBytes(objectMapper.createObjectNode());
        } else if (response.statusCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
            inputStream = response.body();
            dataBytes = readBytes(inputStream);
        } else {
            inputStream = response.body();
            dataBytes = readBytes(inputStream);
        }
        return dataBytes;
    }

    /**
     * This method will do a receive the message from the particular URL connection.
     * <p>
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

    /**
     *
     * <p>
     * Generate token
     * </p>
     *
     * @param protocolType              HTTP/HTTPS
     * @param baseUrlDomainName         host name
     * @param baseUrlApplicationName    app name
     * @param tokenServices             token services
     * @param authUsername              user name for auth
     * @param authPassword              password for auth
     * @param baseUrlversionNo
     * @param baseUrlmethodType
     * @return token
     * @throws TokenGenerationFailure if failed
     */
    @SuppressWarnings("unchecked")
    public String generateToken(final ProtocolType protocolType, final String baseUrlDomainName,
                                final String baseUrlApplicationName, final Object tokenServices, final String authUsername,
                                final String authPassword, final String baseUrlversionNo, final MethodType baseUrlmethodType) throws TokenGenerationFailure {
        String token = null;
        ObjectMapper mapper = null;
        int responseCode = 0;
        StringBuilder content = null;
        URLConnection connection;
        MethodType methodType;
        Map<String, String> tokenParams = null;
        try {
            URI uri;
            if (tokenServices instanceof TokenBean tokenServicesBean) {
                uri = URI.create(protocolType.getProtocol() + tokenServicesBean.getDomainName()
                        + HTTPConstants.SEPARATOR.value() + tokenServicesBean.getAppName()
                        + HTTPConstants.SEPARATOR.value() + tokenServicesBean.getVersionNo()
                        + HTTPConstants.SEPARATOR.value() + tokenServicesBean.getServicePath());
                tokenParams = mapper.readValue(tokenServicesBean.getAdditionalTokenParams().getBytes(), Map.class);
                methodType = MethodType.getMethodType(tokenServicesBean.getMethodType());
            } else {
                uri = URI.create(protocolType.getProtocol() + baseUrlDomainName + HTTPConstants.SEPARATOR.value()
                        + baseUrlApplicationName + HTTPConstants.SEPARATOR.value() + baseUrlversionNo
                        + HTTPConstants.SEPARATOR.value() + (String) tokenServices);
                methodType = baseUrlmethodType;
            }
            // Build HttpRequest
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(uri)
                    .header(HTTPConstants.USERNAME.value(), authUsername)
                    .header(HTTPConstants.PASSWORD.value(), authPassword)
                    .header(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.DEFUALT_CHARSET.value());

            // Add custom headers
            if (tokenParams != null) {
                for (Map.Entry<String, String> entry : tokenParams.entrySet()) {
                    requestBuilder.header(entry.getKey(), entry.getValue());
                }
            }

            // Set the method type (GET, POST, etc.)
            if (methodType == MethodType.POST) {
                requestBuilder.POST(HttpRequest.BodyPublishers.noBody());
            } else if (methodType == MethodType.PUT) {
                requestBuilder.PUT(HttpRequest.BodyPublishers.noBody());
            } else {
                requestBuilder.GET();
            }

            baseRequest = requestBuilder.build();

            // Send the request
            HttpResponse<String> response = httpClient.send(baseRequest, HttpResponse.BodyHandlers.ofString());

            // Check the response code
            if (response.statusCode() != 200) {
                token = "Failure";
            } else {
                token = response.body();
                Map<String, String> responseMap = mapper.readValue(token, Map.class);
                token = responseMap.get("Token");
            }
        } catch (IOException ioe) {
            throw new TokenGenerationFailure("Unble to genearate the token", ioe);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        return token;
    }

    /**
     *
     * <p>
     * Generate token
     * </p>
     *
     * @param protocolType              HTTP/HTTPS
     * @param baseUrlDomainName         host name
     * @param baseUrlApplicationName    app name
     * @param tokenServices             token services
     * @param authUsername                  username for auth
     * @param authPassword                  password for auth
     * @param baseUrlversionNo
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
                                     final boolean skipCertVerify) throws TokenGenerationFailure{
        String token = null;
        final HttpRequest httpRequest;
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
                httpRequest = OpenConnection(tokenServicesBean.getDomainName(), protocolType,
                        urlCompleteData.toString());
                try {
                    if (tokenServicesBean.getAdditionalTokenParams() != null)
                        tokenParams = new ObjectMapper()
                                .readValue(tokenServicesBean.getAdditionalTokenParams().getBytes(), Map.class);
                } catch (IOException e) {
                    logger.error(msgId + " Exception occured in this block for Json message for additional token params ", CLASSNAME, e);
                }
                methodType = MethodType.getMethodType(tokenServicesBean.getMethodType());
            } else {
                httpRequest = OpenConnection(baseUrlDomainName, protocolType,
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

                token = doHttpOperation(baseRequest, msgId, logToken, methodType, reqMessageBytes);


            } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        return token;
    }

    /**
     * <p>
     * Performs the operations based on Https Connection
     * </p>
     *
     *
     * @param baseRequest
     * @param msgId
     * @param logToken
     * @param sslParamsBean
     * @param methodType
     * @param reqMessageBytes
     * @return
     * @throws IOException
     */
    private String doHttpsOperation(final HttpRequest baseRequest, final String msgId, final String logToken,
                                    final SslParamsBean sslParamsBean, final MethodType methodType, final byte[] reqMessageBytes)
            throws IOException, InterruptedException {

        // Build SSLContext
        HttpClient.Builder clientBuilder = HttpClient.newBuilder();
        if (sslParamsBean.getKeyAlias() != null && StringUtils.hasText(sslParamsBean.getKeyAlias())
                && sslParamsBean.getProtocolType() == ProtocolType.HTTPS) {
            SSLContext sslContext = SslHelper.loadSSLcertificate(sslParamsBean.getKeyAlias(), sslParamsBean.isSkipCertVerify());
            clientBuilder.sslContext(sslContext);
        }

        logger.info(msgId + "URL Request Sent: " + baseRequest.uri().toString(), CLASSNAME, logToken);

        if(logger.isDebug()){
            logger.debug(msgId + "Token Request Message: " + ByteUtils.copyBytesAsString(reqMessageBytes, 0), CLASSNAME, logToken);
        }

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(baseRequest.uri())
                .header(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.URLENCODED.value())
                .method(methodType != null ? methodType.getMethodType() : "GET", HttpRequest.BodyPublishers.ofByteArray(reqMessageBytes));

        logger.info(msgId + " Url request sent : " + baseRequest.uri().toString(), CLASSNAME, logToken);

        if (Logger.isDebug())
            logger.debug(msgId + "Token request message " + ByteUtils.copyBytesAsString(reqMessageBytes, 0), CLASSNAME, logToken);

        HttpRequest request = requestBuilder.build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        int responseCode = response.statusCode();
        String token = null;
        if (responseCode != HttpURLConnection.HTTP_OK) {
            logger.info(msgId + "Auth token call response " + responseCode, CLASSNAME, logToken);
            throw new TokenGenerationFailure("Auth token getting failure : Response " + responseCode);
        } else {
            String content = response.body();
            token = getTokenValue(content, msgId, logToken);
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
     * @param baseRequest
     * @param msgId
     * @param logToken
     * @param methodType
     * @param reqMessageBytes
     * @return
     * @throws IOException
     */
    private String doHttpOperation(final HttpRequest baseRequest, final String msgId, final String logToken,
                                   final MethodType methodType, final byte[] reqMessageBytes) throws IOException, InterruptedException {

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(baseRequest.uri())
                .header(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.URLENCODED.value())
                .method(methodType != null ? methodType.getMethodType() : "GET", HttpRequest.BodyPublishers.ofByteArray(reqMessageBytes));

        logger.info(msgId + " Url request sent : " + baseRequest.uri().toString(), CLASSNAME, logToken);

        if (Logger.isDebug())
            logger.debug(msgId + "Token request message " + ByteUtils.copyBytesAsString(reqMessageBytes, 0), CLASSNAME, logToken);

        HttpRequest request = requestBuilder.build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        int responseCode = response.statusCode();
        String token = null;
        if (responseCode != HttpURLConnection.HTTP_OK) {
            logger.info(msgId + "Auth token call response " + responseCode, CLASSNAME, logToken);
            throw new TokenGenerationFailure("Auth token getting failure : Response " + responseCode);
        } else {
            String content = response.body();
            token = getTokenValue(content, msgId, logToken);
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
    static String getTokenValue(final String tokenResponse, final String msgId, final String logToken) {
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


