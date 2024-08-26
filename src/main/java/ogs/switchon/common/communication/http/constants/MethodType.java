package ogs.switchon.common.communication.http.constants;

/**
 * Enum class will define the URL/API method type list
 */
public enum MethodType {
	GET("GET"), POST("POST"), PUT("PUT");

	/**
	 * HTTP Method type
	 */
	private final String methodType;

	/**
	 * Constructor
	 * 
	 * @param methodType http method type
	 */
	MethodType(final String methodType) {
		this.methodType = methodType;
	}

	public String getMethodType() {
		return methodType;
	}

	/**
	 * Helps to get the method implementation
	 * 
	 * @param methodType http method type
	 * @return Object
	 */
	public static MethodType getMethodType(final int methodType) {
		MethodType type;
		switch (methodType) {
		case 0:
			type = MethodType.GET;
			break;
		case 1:
			type = MethodType.POST;
			break;
		case 2:
			type = MethodType.PUT;
			break;
		default:
			type = MethodType.POST;
			break;
		}
		return type;
	}
}
