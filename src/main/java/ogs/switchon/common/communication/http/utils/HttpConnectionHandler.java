package ogs.switchon.common.communication.http.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import ogs.switchon.common.communication.http.J_CommunicationHandler;
import ogs.switchon.common.communication.http.TokenBean;
import ogs.switchon.common.communication.http.constants.HTTPConstants;
import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.communication.http.exception.TokenGenerationFailure;
import ogs.switchon.common.logger.Logger;
import ogs.switchon.common.shared.CommonAppConstants;
import ogs.switchon.common.utilities.ByteUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@SuppressWarnings("serial")
public class HttpConnectionHandler implements J_CommunicationHandler {
    private static final String CLASSNAME = "HCHD";
    protected static Logger logger = Logger.getLogger();
    /**
     * Maximum buffer size
     */
    private static final int MAX_BUFFER_SIZE = 9216;

    @Override
    public HttpRequest.Builder OpenConnection(final String domainName, final ProtocolType protocolType, final String servicePath) throws IOException, InterruptedException {
        Objects.requireNonNull(domainName, "URL Domain name is NULL");

        final String url = protocolType.getProtocol() + domainName + HTTPConstants.SEPARATOR.value() + servicePath;
        return HttpRequest.newBuilder()
                .uri(URI.create(url));
    }

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

    public byte[] read(final HttpResponse<InputStream> response, final ObjectMapper objectMapper) throws IOException {
        byte[] dataBytes;

        if (response.statusCode() == HttpURLConnection.HTTP_ACCEPTED) {
            dataBytes = objectMapper.writeValueAsBytes(objectMapper.createObjectNode());
        } else {
            dataBytes = readBytes(response.body());
        }

        return dataBytes;
    }

    public byte[] writeAndRead(final HttpClient httpClient, final HttpRequest request, final byte[] msgDataBytes, final String logId, final String logToken,
                        final ObjectMapper objectMapper) throws IOException, InterruptedException {
        byte[] dataBytes;
        HttpResponse<InputStream> response = null;

        Objects.requireNonNull(request, "Request is NULL");

        if (!request.method().equalsIgnoreCase(MethodType.GET.getMethodType())) {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());

            logger.info(logId, "Written bytes length: " + msgDataBytes.length, CLASSNAME, logToken);

            if (CommonAppConstants.isRawMsgDisplay && Logger.isDebug()) {
                logger.debug("Written message: " + ByteUtils.copyBytesAsString(msgDataBytes, 0), CLASSNAME, logToken);
            }
        }

        if (response != null) {
            if (response.statusCode() == HttpURLConnection.HTTP_ACCEPTED) {
                dataBytes = objectMapper.writeValueAsBytes(objectMapper.createObjectNode());
            } else {
                dataBytes = read(response, objectMapper);
            }
        } else {
            throw new IllegalStateException("Response is null after the request.");
        }

        return dataBytes;
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
        HttpClient httpClient = HttpClient.newHttpClient();
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

            HttpResponse<String> response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());

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
        HttpClient httpClient = HttpClient.newHttpClient();
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