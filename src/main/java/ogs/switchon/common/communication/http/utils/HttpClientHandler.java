package ogs.switchon.common.communication.http.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import ogs.switchon.common.communication.http.J_ClientHandler;
import ogs.switchon.common.communication.http.SslParamsBean;
import ogs.switchon.common.communication.http.TokenBean;
import ogs.switchon.common.communication.http.constants.HTTPConstants;
import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.communication.http.exception.TokenGenerationFailure;
import ogs.switchon.common.logger.Logger;
import ogs.switchon.common.modules.security.SslHelper;
import ogs.switchon.common.shared.CommonAppConstants;
import ogs.switchon.common.utilities.ByteUtils;
import org.springframework.util.StringUtils;

import javax.net.ssl.SSLContext;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static ogs.switchon.common.communication.http.utils.HttpRequestHeaderHelper.setHttpHeader;

public class HttpClientHandler implements J_ClientHandler {
    private HttpClient httpClient;
    private HttpRequest baseRequest;
    private static final String CLASSNAME = "HCHD";
    private String token;
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

    public HttpClientHandler() {
        this.httpClient = HttpClient.newHttpClient();
    }

    @Override
    public HttpRequest OpenConnection(final String domainName, final ProtocolType protocolType, final String servicePath) throws IOException, InterruptedException {
        Objects.requireNonNull(domainName, "URL Domain name is NULL");

        final String url = protocolType.getProtocol() + domainName + HTTPConstants.SEPARATOR.value() + servicePath;
        baseRequest = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build();
        return baseRequest;
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
    public byte[] writeAndRead(final BufferedOutputStream outputStream,
                               final byte[] msgDataBytes, final String logId, final String logToken,
                               final ObjectMapper objectMapper) throws IOException, InterruptedException {
        byte[] dataBytes;
        HttpResponse<InputStream> response = null;
        InputStream inputStream;

        if (!baseRequest.method().equalsIgnoreCase(MethodType.GET.getMethodType())) {
            Objects.requireNonNull(outputStream, "Output Stream is NULL");

            HttpRequest request = createRequestWithHeaders(baseRequest, msgDataBytes, logId, logToken, null, "POST");

            response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());

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

    private HttpRequest createRequestWithHeaders(HttpRequest baseRequest, byte[] msgDataBytes, String logId, String logToken, String additionalTokenFields, String method) throws IOException {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(baseRequest.uri());

        if ("POST".equalsIgnoreCase(method)) {
            requestBuilder.method("POST", HttpRequest.BodyPublishers.ofByteArray(msgDataBytes));
        } else if ("GET".equalsIgnoreCase(method)) {
            requestBuilder.GET();
        } else {
            throw new IllegalArgumentException("Unsupported HTTP method: " + method);
        }

        setHttpHeader(requestBuilder, new String(msgDataBytes), logId, logToken, additionalTokenFields);

        return requestBuilder.build();
    }

    public HttpClient httpClientWithSSL(SslParamsBean sslParamsBean) throws Exception {
        HttpClient.Builder clientBuilder = HttpClient.newBuilder();
        if (sslParamsBean.getKeyAlias() != null && StringUtils.hasText(sslParamsBean.getKeyAlias())
                && sslParamsBean.getProtocolType() == ProtocolType.HTTPS) {
            SSLContext sslContext = SslHelper.loadSSLcertificate(sslParamsBean.getKeyAlias(), sslParamsBean.isSkipCertVerify());

            clientBuilder.sslContext(sslContext);
        }
        clientBuilder.connectTimeout(Duration.ofSeconds(10));
        return clientBuilder.build();
    }


    /**
     * This method will do a receive the message from the particular Http connection.
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
        String token;
        ObjectMapper mapper = null;
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
                        + HTTPConstants.SEPARATOR.value() + tokenServices);
                methodType = baseUrlmethodType;
            }

            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(uri)
                    .header(HTTPConstants.USERNAME.value(), authUsername)
                    .header(HTTPConstants.PASSWORD.value(), authPassword)
                    .header(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.DEFUALT_CHARSET.value());

            if (tokenParams != null) {
                for (Map.Entry<String, String> entry : tokenParams.entrySet()) {
                    requestBuilder.header(entry.getKey(), entry.getValue());
                }
            }

            if (methodType == MethodType.POST) {
                requestBuilder.POST(HttpRequest.BodyPublishers.noBody());
            }  else {
                requestBuilder.GET();
            }

            baseRequest = requestBuilder.build();

            HttpResponse<String> response = httpClient.send(baseRequest, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                token = "Failure";
            } else {
                token = response.body();
                Map<String, String> responseMap = mapper.readValue(token, Map.class);
                token = responseMap.get("Token");
            }
        } catch (IOException ioe) {
            throw new TokenGenerationFailure("Unable to generate the token", ioe);
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
                                     final boolean skipCertVerify) throws TokenGenerationFailure {
        String token = null;
        HttpRequest.Builder requestBuilder;
        MethodType methodType;
        Map<String, String> tokenParams = new HashMap<>();
        StringBuilder postData = new StringBuilder();

        try {
            URI uri;
            if (tokenServices instanceof TokenBean tokenServicesBean) {
                uri = URI.create(protocolType.getProtocol() + tokenServicesBean.getDomainName()
                        + HTTPConstants.SEPARATOR.value() + tokenServicesBean.getAppName()
                        + HTTPConstants.SEPARATOR.value() + tokenServicesBean.getVersionNo()
                        + HTTPConstants.SEPARATOR.value() + tokenServicesBean.getServicePath());
                tokenParams = new ObjectMapper().readValue(tokenServicesBean.getAdditionalTokenParams().getBytes(), Map.class);
                methodType = MethodType.getMethodType(tokenServicesBean.getMethodType());
            } else {
                uri = URI.create(protocolType.getProtocol() + baseUrlDomainName + HTTPConstants.SEPARATOR.value()
                        + baseUrlApplicationName + HTTPConstants.SEPARATOR.value() + baseUrlversionNo
                        + HTTPConstants.SEPARATOR.value() + tokenServices);
                methodType = baseUrlmethodType;
            }

            requestBuilder = HttpRequest.newBuilder()
                    .uri(uri)
                    .header(HTTPConstants.USERNAME.value(), authUsername)
                    .header(HTTPConstants.PASSWORD.value(), authPassword)
                    .header(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.DEFUALT_CHARSET.value());

            if (tokenParams != null) {
                for (Map.Entry<String, String> entry : tokenParams.entrySet()) {
                    requestBuilder.header(entry.getKey(), entry.getValue());
                }
            }

            byte[] reqMessageBytes;
            if (tokenMessageBytes == null) {
                for (Map.Entry<String, String> param : tokenParams.entrySet()) {
                    if (postData.length() != 0) postData.append('&');
                    postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
                    postData.append('=');
                    postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
                }
                reqMessageBytes = postData.toString().getBytes();
            } else {
                reqMessageBytes = tokenMessageBytes.getBytes();
            }

            if (methodType == MethodType.POST) {
                requestBuilder.POST(HttpRequest.BodyPublishers.ofByteArray(reqMessageBytes));
            } else {
                requestBuilder.GET();
            }

            HttpRequest request = requestBuilder.build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // Handle the response
            if (response.statusCode() != 200) {
                token = "Failure";
            } else {
                token = response.body();
                Map<String, String> responseMap = new ObjectMapper().readValue(token, Map.class);
                token = responseMap.get("Token");
            }
        } catch (IOException | InterruptedException e) {
            throw new TokenGenerationFailure("Unable to generate OAuth token", e);
        }
        return token;
    }

}