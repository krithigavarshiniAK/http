package ogs.switchon.common.communication.http;

import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;

import org.hibernate.mapping.List;
import org.junit.Assert;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.mysql.cj.x.protobuf.MysqlxDatatypes.Array;

import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.exceptions.InvalidBufferStream;
import ogs.switchon.common.exceptions.SocketClosedException;
import ogs.switchon.common.logger.builder.LogBuilder;
import ogs.switchon.common.logger.constants.BaseFolderSuffixFormat;
import ogs.switchon.common.logger.constants.LogFrequencies;
import ogs.switchon.common.modules.security.SslHelper;
import ogs.switchon.common.modules.security.constants.KeyStore;
import ogs.switchon.common.shared.ApplicationData;
import ogs.switchon.common.shared.CommonAppConstants;
import ogs.switchon.common.utilities.ColorConsoleUtils;

/**
 * This class is used to test the http connection
 *
 */
class ConnectionHandlerTest {

	/**
	 * domain name variable
	 */
	private static String domainName = ""; // Provide domain name in the format{ip:port}
	/**
	 * app name variable
	 */
	private static String appName = "DataExtract";
	/**
	 * service path variable
	 */
	private static String servicePath = "getExtractMessage";
	/**
	 * version number variable
	 */
	private static String versionNo = "v1";
	/**
	 * json content type variable
	 */
	private static String contentType = "application/json";
	/**
	 * log token object
	 */
	private static String logToken;

	/**
	 * This method is used to test teh http requests and response
	 */
	@Disabled
	@Test
	public void testHttpAPIRequestandResponse() {
		final LogBuilder logBuilder = LogBuilder.createLogGroup(CommonAppConstants.HOME_DIR + File.separator + "Http",
				"JSONTest", BaseFolderSuffixFormat.YYYYMMDD.getDateFormat());
		logToken = logBuilder.addLogFile(".log", "Junit", "Log_", LogFrequencies._15MINS);
		ApplicationData appdata= null;
		assertAll(() -> {
			final String request = "{\n" + "\"CustomerId\":\"1100008\",\n" + "\"BranchCode\":\"100062\",\n"
					+ "\"CardNumber\":\"601070525912\",\n" + "\"AccountNumber\":\"601070525912\",\n"
					+ "\"AccountHolderName\":\"Customer\",\n" + "\"AccountType\":\"10\",\n" + "\"CardType\":\"D\"\n"
					+ "}";
			final byte[] requestMessage = request.getBytes();
			final ConnectionHandler handlerBean = new ConnectionHandler(domainName, contentType, 1, false, null, null,
					null, appName, versionNo, servicePath, 30, 30, null, null, null, logToken, request, null, 0, 10l, 30,
					null, null, null, false);
			final ConnectionHandler connectionHandler = (ConnectionHandler) handlerBean;
			final byte[] receivedMessage = connectionHandler.doRequest(logToken, requestMessage, null, appdata, null);
			ColorConsoleUtils.printInfo(receivedMessage != null ? new String(receivedMessage) : null);
		});
	}

	/**
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws SocketClosedException
	 * @throws InvalidBufferStream
	 */
	@Disabled
	@Test
	public void name() throws MalformedURLException, IOException, SocketClosedException, InvalidBufferStream {
		final ConnectionHandler connectionHandler = new ConnectionHandler(domainName, contentType, 1, false, null, null,
				null, appName, versionNo, servicePath, 30, 30, null, null, null, logToken, "", null, 0, 10l, 30, null, null,
				null, false);
		connectionHandler.pushRequest("".getBytes(), "http://192.168.36.101:8324/BPUAT/Test", MethodType.POST, 30,
				new HashMap<String, String>());
		Assert.assertFalse(false);
	}

	/**
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws SocketClosedException
	 * @throws InvalidBufferStream
	 */
	@Disabled
	@Test
	public void processSecureHttp()
			throws MalformedURLException, IOException, SocketClosedException, InvalidBufferStream {
		final ConnectionHandler connectionHandler = new ConnectionHandler(domainName, contentType, 1, false, null, null,
				null, appName, versionNo, servicePath, 30, 30, null,null, null, logToken, "", null, 0, 10l, 30, null, null,
				null, false);
		connectionHandler.pushSecuredRequest("".getBytes(),
				"https://uatapp.bijlipay.co.in:9090/api/bijlipay/1/merchant/cashBackStatus", MethodType.POST,
				new HashMap<String, String>(), null, false, 30);
		Assert.assertFalse(false);
	}

	@Disabled
	@Test
	public void process3DSHttps() {
		final String fullUrl = "https://3dss.prev.netcetera-payment.ch/3ds-server/3ds/versioning";
		
		try {
			SslHelper.loadKeyStore(KeyStore.KEY_STORE_NAME.getValue(), KeyStore.KEY_STORE_SECRET.getValue());
			SslHelper.loadTrustStore(KeyStore.TRUST_STORE_NAME.getValue(), KeyStore.TRUST_STORE_SECRET.getValue());
			byte[] response = new ConnectionHandler(domainName, contentType, 1, false, null, null, null, appName,
					versionNo, servicePath, 30, 30, null,null, null, logToken, "", null, 0, 10l, 30, null, null, null, false)
							.pushSecuredRequest(
									("{\"threeDSServerTransID\":\"" + UUID.randomUUID()
											+ "\",\"cardholderAccountNumber\":\"4556557955726624\"}").getBytes(),
									fullUrl, MethodType.POST, new HashMap<>(), "de92c912-c55d-4342-be04-64e2abcaa6e6",
									true);
			System.err.println(new String(response));
		} catch (IOException | SocketClosedException | InvalidBufferStream e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	@Disabled
	@Test
	public void processConsctructURlusingAppdata() {
		String fullUrl = "https://3dss.prev.netcetera-payment.ch/3ds-server/3ds/$P{'156'}/versioning";
//		ConnectionHandler connectionHandler  = new ConnectionHandler();
		AppData appData = new AppData(new ArrayList<Integer>());
		appData.addInAppData(156, "88");
		try {
//			fullUrl = connectionHandler.replaceAppVariables(fullUrl, appData);
			System.err.println(fullUrl);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
  @Disabled
	@Test
	public void processConsctructURlAppending() {
		String fullUrl = "https://3dss.prev.netcetera-payment.ch/3ds-server/3ds/{156}/versioning/{169}";
		String additionalparams = "request_id=15,request_Type=157";
		ConnectionHandler connectionHandler  = new ConnectionHandler(additionalparams, additionalparams, null, false, additionalparams, additionalparams, additionalparams, additionalparams, additionalparams, additionalparams, null, null, additionalparams, additionalparams, additionalparams, additionalparams, additionalparams, null, null, null, fullUrl, null, additionalparams, false);
		AppData appData = new AppData(new ArrayList<Integer>());
		appData.addInAppData(15, "Manoj");
		appData.addInAppData(157, "johnBasha");
		appData.addInAppData(169, "Importing");
		appData.addInAppData(156, "Vinay");
		
		
		try {
			additionalparams = connectionHandler.assignDefaultSwitchvariables(additionalparams, appData);
			fullUrl+=additionalparams;
			System.err.println(fullUrl);
			fullUrl = connectionHandler.replaceAppVariables(fullUrl, appData);
			System.err.println(fullUrl);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
