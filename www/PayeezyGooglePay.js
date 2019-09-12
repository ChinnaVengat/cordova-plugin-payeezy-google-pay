var SGAP = {
    
    isReadyToPay: function () {
      return new Promise(function (resolve, reject) {
        cordova.exec(resolve, reject, 'PayeezyGooglePay', 'is_ready_to_pay', [])
      })
    },
    requestPayment: function (paymentDetails) {
      return new Promise(function (resolve, reject) {
        cordova.exec(resolve, reject, 'PayeezyGooglePay', 'request_payment', [ paymentDetails ])
      })
    }
  }
  
  module.exports = SGAP
  