# cordova-plugin-payeezy-google-pay
Cordova plugin for Payeezy Google pay integration

## Notes

This plugin only supports Android.

This plugin will add these dependencies to your build.gradle file:

```
com.google.android.gms:play-services-wallet:15.0.1
com.android.support:support-v4:27.0.2
com.android.support:appcompat-v7:27.1.1
compile 'com.android.volley:volley:1.0.0'
```

## Installation

```
cordova plugin add cordova-plugin-payeezy-google-pay
```

## Usage

This plugin puts the functions into `window.sgap`.
All functions return a promise.

```
sgap.isReadyToPay()
```
 - Used to test if the appropriate payment method is available on the current device.
 - Resolves if appropriate payment method is available
 - Rejects if not, or if it encounters an error

```
sgap.requestPayment(
   {
      price: "12.50",
      api_key: "alknk2jb34kj2b3lk4jbkjsbf",
      api_secret: "adee123abc13ba41cabc41bc34cba1c34bca123bc",
      country_code: "US",
      currency_code: "USD",
      environment: "CERT",
      merchant_id: "3176752645",
      merchant_ref: "Company Name",
      merchant_token: "fdoa-1ab34ac1234c1b23b4c1b34a1bc3cb11c34bc1b34a",
      transaction_type: "purchase",
      url:'https://api-cert.payeezy.com/v1/transactions'
});
```
      
  - Initiates the payment journey for the user to complete.
  - `price` must be a string representation of the total price - e.g. for £10.78, it would be `10.78`
  - `currency_code` must be a valid ISO 4217 currency code for the transaction
  - Resolves when the journey is complete, with the stripe token
  - Rejects if an error occurs

## Contributing

PRs welcome!

## License

MIT
