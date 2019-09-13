package payeezygooglepay;

import android.app.Activity;
import android.content.Intent;
import android.util.Base64;
import android.util.Log;
import android.os.Bundle;

import com.android.volley.AuthFailureError;
import com.android.volley.DefaultRetryPolicy;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.identity.intents.model.UserAddress;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.wallet.AutoResolveHelper;
import com.google.android.gms.wallet.CardInfo;
import com.google.android.gms.wallet.CardRequirements;
import com.google.android.gms.wallet.PaymentData;
import com.google.android.gms.wallet.PaymentDataRequest;
import com.google.android.gms.wallet.PaymentMethodTokenizationParameters;
import com.google.android.gms.wallet.PaymentsClient;
import com.google.android.gms.wallet.TransactionInfo;
import com.google.android.gms.wallet.Wallet;
import com.google.android.gms.wallet.WalletConstants;
import com.google.android.gms.wallet.IsReadyToPayRequest;
import com.google.android.gms.wallet.PaymentMethodToken;
import com.google.android.gms.wallet.ShippingAddressRequirements;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.util.Arrays;

public class PayeezyGooglePay extends CordovaPlugin {
  private static final String IS_READY_TO_PAY = "is_ready_to_pay";
  private static final String REQUEST_PAYMENT = "request_payment";
  private static final BigDecimal MICROS = new BigDecimal(1000000d);
  private static final int LOAD_PAYMENT_DATA_REQUEST_CODE = 42;

  private PaymentsClient paymentsClient = null;
  private PaymentsClient mPaymentsClient = null;
  private static CallbackContext callback;
  private int environment;
  private static String api_key,api_secret,country_code,currency_code,environments,merchant_id,merchant_ref,merchant_token,url;
  private static String price;

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);
  }

  @Override
  public boolean execute(final String action, JSONArray data, CallbackContext callbackContext) throws JSONException {
    callback = callbackContext;

    this.mPaymentsClient = Wallet.getPaymentsClient(
        this.cordova.getActivity().getApplicationContext(),
        new Wallet.WalletOptions.Builder()
            .setEnvironment(WalletConstants.ENVIRONMENT_TEST)
            .build());

    if (action.equals(IS_READY_TO_PAY)) {
      this.isReadyToPay();
    } else if (action.equals(REQUEST_PAYMENT)) {
      this.requestPayment(data.getJSONObject(0));
    } else {
      return false;
    }
    return true;
  }

  private boolean isInitialised() {
    return this.paymentsClient == null;
  }


  private void isReadyToPay() {
    IsReadyToPayRequest request = IsReadyToPayRequest.newBuilder()
      .addAllowedPaymentMethod(WalletConstants.PAYMENT_METHOD_CARD)
      .addAllowedPaymentMethod(WalletConstants.PAYMENT_METHOD_TOKENIZED_CARD)
      .build();

    Task<Boolean> task = mPaymentsClient.isReadyToPay(request);
    final CallbackContext callbackContext = callback;
    task.addOnCompleteListener(
      new OnCompleteListener<Boolean>() {
        public void onComplete(Task<Boolean> task) {
          try {
            boolean result = task.getResult(ApiException.class);
            if (!result) callbackContext.error("Not supported");
            else callbackContext.success("isReadyToPay success");

          } catch (ApiException exception) {
            callbackContext.error(exception.getMessage());
          }
        }
      });
  }

  private void requestPayment (JSONObject paymentDetails) {
    // PaymentDataRequest request = this.createPaymentDataRequest(totalPrice, currency);
    try {
    price = paymentDetails.getString("price");
    //  try {
    //         Double.parseDouble(this.price);
    //     } catch (NumberFormatException e) {
    //          callbackContext.error("Invalid amount");
    //         return;
    //     }
    api_key = paymentDetails.getString("api_key");
    api_secret = paymentDetails.getString("api_secret");
    country_code = paymentDetails.getString("country_code");
    currency_code = paymentDetails.getString("currency_code");
    environments = paymentDetails.getString("environment");
    merchant_id = paymentDetails.getString("merchant_id");
    merchant_ref = paymentDetails.getString("merchant_ref");
    merchant_token = paymentDetails.getString("merchant_token");
    url = paymentDetails.getString("url");

    TransactionInfo transaction = this.createTransaction(price,currency_code);
        PaymentDataRequest request = this.createPaymentDataRequest(transaction);
    Activity activity = this.cordova.getActivity();
    if (request != null) {
      cordova.setActivityResultCallback(this);
      AutoResolveHelper.resolveTask(
      mPaymentsClient.loadPaymentData(request),
          activity,
          LOAD_PAYMENT_DATA_REQUEST_CODE);
    }
    } catch (JSONException e) {
      callback.error(e.getLocalizedMessage());
    }
  }

  @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {

        switch (requestCode) {
            case LOAD_PAYMENT_DATA_REQUEST_CODE:
                switch (resultCode) {
                    case Activity.RESULT_OK:

                        PaymentData paymentData = PaymentData.getFromIntent(data);

                        PaymentMethodToken token = paymentData.getPaymentMethodToken();

        // getPaymentMethodToken will only return null if PaymentMethodTokenizationParameters was
        // not set in the PaymentRequest.
        if (token != null) {
            String billingName = paymentData.getCardInfo().getBillingAddress().getName();
             this.sendRequestToFirstData(paymentData);
            // callback.success("PaymentMethodToken received");
        }

                        break;
                    case Activity.RESULT_CANCELED:
                        // Nothing to here normally - the user simply cancelled without selecting a
                        // payment method.
                         callback.error("In cancelled!!");
                        break;
                    case AutoResolveHelper.RESULT_ERROR:
                        
                        Status status = AutoResolveHelper.getStatusFromIntent(data);
                         callback.error("loadPaymentData failed");
                        // ,status.getStatusCode()
                        
                        break;
                }

                // Re-enables the Pay with Google button.
                // mPwgButton.setClickable(true);
                break;
        }
    }

  /*******
     *Added for FD processing
     */
    /**
     * Send a request to the First Data server to process the payment. The REST request
     * includes HTTP headers that identify the developer and the merchant issuing the request:
     * <ul>
     * <li>{@code apikey} - identifies the developer</li>
     * <li>{@code token} - identifies the merchant</li>
     * </ul>
     * The values for the two headers are provided by First Data.
     * <p>
     * The token created is extracted from the paymentData object. The token
     * is in JSON format and consists of the following fields:
     * <ul>
     * <li>{@code signedMessage} - the encrypted details of the transaction</li>
     * <li>{@code protocolVersion} - protocolVersion indicationg it is GooglePay Payload
     *</li>
     * <li>{@code signature} - a signature field-signed Message</li>
     * </ul>
     * These items, are used
     * to create the transaction payload. The payload is sent to the First Data servers
     * for execution.
     * </p>
     *
     * @param paymentData PaymentData object
     * //@param env        First Data environment to be used
     */
    public void sendRequestToFirstData(final PaymentData paymentData) {
        // callback.success("sendRequestToFirstData");
        try {
            //  Parse the Json token retrieved
            String tokenJSON = paymentData.getPaymentMethodToken().getToken();
            final JSONObject jsonObject = new JSONObject(tokenJSON);

            String signedMessage=jsonObject.getString("signedMessage");//contains encryptedMessage, protocolVersion and Signature
            String protocolVersion=jsonObject.getString("protocolVersion");
            String signature = jsonObject.getString("signature");


            //  Create a First Data Json request
            JSONObject requestPayload = this.getRequestPayload(signedMessage, protocolVersion, signature);
            final String payloadString = requestPayload.toString();
            final Map<String, String> HMACMap = this.computeHMAC(payloadString);


            StringRequest request = new StringRequest(
                    Request.Method.POST,this.getUrl(),
                    new Response.Listener<String>() {
                        @Override
                        public void onResponse(String response) {
                            //  request completed - launch the response activity
                            // startResponseActivity("SUCCESS", response);
                             callback.success(response);
                            
                        }
                    },
                    new Response.ErrorListener() {
                        @Override
                        public void onErrorResponse(VolleyError error) {

                            // startResponseActivity("ERROR", formatErrorResponse(error));
                             callback.error(formatErrorResponse(error));
                        }
                    }) {

                @Override
                public String getBodyContentType() {
                    return "application/json";
                }

                @Override
                public byte[] getBody() {
                    try {
                        return payloadString.getBytes("UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        return null;
                    }
                }

                @Override
                public Map<String, String> getHeaders() throws AuthFailureError {
                    Map<String, String> headerMap = new HashMap<String, String>(HMACMap);

                    //  First data issued APIKey identifies the developer
                    headerMap.put("apikey", api_key);

                    //  First data issued token identifies the merchant
                    headerMap.put("token", merchant_token);

                    return headerMap;
                }
            };

            request.setRetryPolicy(new DefaultRetryPolicy(0, -1, DefaultRetryPolicy.DEFAULT_BACKOFF_MULT));
            RequestQueue queue = Volley.newRequestQueue(this.cordova.getActivity().getApplicationContext());

            queue.add(request);

        } catch (JSONException e) {
            // Toast.makeText(CheckoutActivity.this, "Error parsing JSON payload", Toast.LENGTH_LONG).show();
            callback.error("Error parsing JSON payload");
        }
    }

    /**
     * Convert JSON object into a String.
     * @param jo    JSON object
     * @return  String representation of the object
     */
    private String formatResponse(JSONObject jo) {
        try {
            return jo.toString(2);
        } catch (JSONException e) {
            return "Invalid JSON response";
        }
    }

    private String formatErrorResponse(VolleyError ve) {
        return String.format("Status code = %d%nError message = %s",
                ve.networkResponse.statusCode, new String(ve.networkResponse.data));
    }

     private static String getUrl() {
        return url;
    }

    private String formatAmount(String amount) {
        BigDecimal a = new BigDecimal(amount);
        BigDecimal scaled = a.setScale(2, BigDecimal.ROUND_HALF_EVEN);
        return scaled.toString().replace(".", "");
    }


  /**
     *
     * @param signedMessage
     * @param protocolVersion
     * @param signature
     * @return
     */
    private JSONObject getRequestPayload(String signedMessage, String protocolVersion, String signature) {
        Map<String, Object> pm = new HashMap<String, Object>();
        pm.put("merchant_ref", "orderid");
        pm.put("transaction_type", "purchase");
        pm.put("method", "3DS");
        pm.put("amount", formatAmount(price));
        pm.put("currency_code", "USD");

        Map<String, Object> ccmap = new HashMap<String, Object>();
        ccmap.put("type", "G");             //  Identify the request as Android Pay request
        ccmap.put("version", protocolVersion); // New field "version" identifies Android or Google Pay
        ccmap.put("data", signedMessage);
        ccmap.put("signature", signature); // This is a new field "signature"

        pm.put("3DS", ccmap);
        return new JSONObject(pm);
    }

    /**
     * Compute HMAC signature for the payload. The signature is based on the APIKey and the
     * APISecret provided by First Data. If the APISecret is not specified, the HMAC is
     * not computed.
     *
     * @param payload The payload as a String
     * @return Map of HTTP headers to be added to the request
     */
    private Map<String, String> computeHMAC(String payload) {

        // EnvProperties ep = EnvData.getProperties(mEnv);
        String apiSecret = api_secret;
        String apiKey = api_key;
        String token = merchant_token;

        Map<String, String> headerMap = new HashMap<String, String>();
        if (apiSecret != null) {
            try {
                String authorizeString;
                String nonce = Long.toString(Math.abs(SecureRandom.getInstance("SHA1PRNG").nextLong()));
                String timestamp = Long.toString(System.currentTimeMillis());

                Mac mac = Mac.getInstance("HmacSHA256");
                SecretKeySpec secretKey = new SecretKeySpec(apiSecret.getBytes(), "HmacSHA256");
                mac.init(secretKey);

                StringBuilder buffer = new StringBuilder()
                        .append(apiKey)
                        .append(nonce)
                        .append(timestamp)
                        .append(token)
                        .append(payload);

                byte[] macHash = mac.doFinal(buffer.toString().getBytes("UTF-8"));
                authorizeString = Base64.encodeToString(bytesToHex(macHash).getBytes(), Base64.NO_WRAP);

                headerMap.put("nonce", nonce);
                headerMap.put("timestamp", timestamp);
                headerMap.put("Authorization", authorizeString);
            } catch (Exception e) {
                //  Nothing to do
            }
        }
        return headerMap;
    }

    private static String bytesToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    /**
     * Creates an instance of {@link PaymentsClient} for use in an {@link Activity} using the
     * environment and theme set in {@link Constants}.
     *
     * @param activity is the caller's activity.
     */
    public static PaymentsClient createPaymentsClient(Activity activity) {
        Wallet.WalletOptions walletOptions = new Wallet.WalletOptions.Builder()
                .setEnvironment(WalletConstants.ENVIRONMENT_TEST)
                .build();
        return Wallet.getPaymentsClient(activity, walletOptions);
    }

    /**
     * Builds {@link PaymentDataRequest} to be consumed by {@link PaymentsClient#loadPaymentData}.
     *
     * @param transactionInfo contains the price for this transaction.
     */
    public static PaymentDataRequest createPaymentDataRequest(TransactionInfo transactionInfo) {
        PaymentMethodTokenizationParameters.Builder paramsBuilder =
                PaymentMethodTokenizationParameters.newBuilder()

                        .setPaymentMethodTokenizationType(
                                WalletConstants.PAYMENT_METHOD_TOKENIZATION_TYPE_PAYMENT_GATEWAY)
                        .addParameter("gateway", "firstdata")
                        .addParameter("gatewayMerchantId", merchant_id);



        /*for (Pair<String, String> param : Constants.GATEWAY_TOKENIZATION_PARAMETERS) {
            paramsBuilder.addParameter(param.first, param.second);
        }
*/
        return createPaymentDataRequest(transactionInfo, paramsBuilder.build());
    }

    /**
     * Builds {@link PaymentDataRequest} for use with DIRECT integration to be consumed by
     * {@link PaymentsClient#loadPaymentData}.
     * <p>
     * Please refer to the documentation for more information about DIRECT integration. The type of
     * integration you use depends on your payment processor.
     *
     * @param transactionInfo contains the price for this transaction.
     */
    public static PaymentDataRequest createPaymentDataRequestDirect(TransactionInfo transactionInfo) {
        PaymentMethodTokenizationParameters params =
                PaymentMethodTokenizationParameters.newBuilder()
                        .setPaymentMethodTokenizationType(
                                WalletConstants.PAYMENT_METHOD_TOKENIZATION_TYPE_DIRECT)

                        // Omitting the publicKey will result in a request for unencrypted data.
                        // Please refer to the documentation for more information on unencrypted
                        // requests.
                        .addParameter("publicKey", "")
                        .build();

        return createPaymentDataRequest(transactionInfo, params);
    }

    private static PaymentDataRequest createPaymentDataRequest(TransactionInfo transactionInfo, PaymentMethodTokenizationParameters params) {
        PaymentDataRequest request =
                PaymentDataRequest.newBuilder()
                        .setPhoneNumberRequired(false)
                        .setEmailRequired(true)
                        .setShippingAddressRequired(false)

                        // Omitting ShippingAddressRequirements all together means all countries are
                        // supported.
                        .setShippingAddressRequirements(
                                ShippingAddressRequirements.newBuilder()
                                        .addAllowedCountryCodes(Arrays.asList(
            "US"//,
//            "GB"
))
                                        .build())

                        .setTransactionInfo(transactionInfo)
                        .addAllowedPaymentMethods(Arrays.asList(
                        WalletConstants.PAYMENT_METHOD_CARD,
                        WalletConstants.PAYMENT_METHOD_TOKENIZED_CARD))
                        .setCardRequirements(
                                CardRequirements.newBuilder()
                                        .addAllowedCardNetworks(Arrays.asList(
                        WalletConstants.CARD_NETWORK_AMEX,
                        WalletConstants.CARD_NETWORK_DISCOVER,
                        WalletConstants.CARD_NETWORK_VISA,
                        WalletConstants.CARD_NETWORK_MASTERCARD))
                                        .setAllowPrepaidCards(true)
                                        .setBillingAddressRequired(true)

                                        // Omitting this parameter will result in the API returning
                                        // only a "minimal" billing address (post code only).
                                       // .setBillingAddressFormat(WalletConstants.BILLING_ADDRESS_FORMAT_FULL)
                                        .build())
                        .setPaymentMethodTokenizationParameters(params)

                        // If the UI is not required, a returning user will not be asked to select
                        // a card. Instead, the card they previously used will be returned
                        // automatically (if still available).
                        // Prior whitelisting is required to use this feature.
                        .setUiRequired(true)
                        .build();

        return request;
    }

    /**
     * Determines if the user is eligible to Pay with Google by calling
     * {@link PaymentsClient#isReadyToPay}. The nature of this check depends on the methods set in
     * {@link Constants#SUPPORTED_METHODS}.
     * <p>
     * If {@link WalletConstants#PAYMENT_METHOD_CARD} is specified among supported methods, this
     * function will return true even if the user has no cards stored. Please refer to the
     * documentation for more information on how the check is performed.
     *
     * @param client used to send the request.
     */
    // public static Task<Boolean> isReadyToPay(PaymentsClient client) {
    //     IsReadyToPayRequest.Builder request = IsReadyToPayRequest.newBuilder();
    //     for (Integer allowedMethod : Constants.SUPPORTED_METHODS) {
    //         request.addAllowedPaymentMethod(allowedMethod);
    //     }
    //     return client.isReadyToPay(request.build());
    // }

    /**
     * Builds {@link TransactionInfo} for use with {@link PaymentsUtil#createPaymentDataRequest}.
     * <p>
     * The price is not displayed to the user and must be in the following format: "12.34".
     * {@link PaymentsUtil#microsToString} can be used to format the string.
     *
     * @param price total of the transaction.
     */
    public static TransactionInfo createTransaction(String price,String currency_code) {
        return TransactionInfo.newBuilder()
                .setTotalPriceStatus(WalletConstants.TOTAL_PRICE_STATUS_FINAL)
                .setTotalPrice(price)
                .setCurrencyCode(currency_code)
                .build();
    }

    /**
     * Converts micros to a string format accepted by {@link PaymentsUtil#createTransaction}.
     *
     * @param micros value of the price.
     */
    // public static String microsToString(long micros) {
    //     return new BigDecimal(micros).divide(MICROS).setScale(2, RoundingMode.HALF_EVEN).toString();
    // }
}
