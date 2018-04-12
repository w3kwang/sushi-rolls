import hashlib
import hmac
import base64
import re
from datetime import datetime
from java.io import PrintWriter
from burp import IBurpExtender
from burp import IHttpListener

# A Burp Extension in Python
#   Intercetp HTTP Requests which contains a HAMC header and re-calculate &
#   update HMAC out of modified message body.
#

class BurpExtender(IBurpExtender, IHttpListener):
    # update me:
    secret = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2SUF2"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Rehash request and update hmac header")
        callbacks.registerHttpListener(self)

        # obtain our output and error streams
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        return

    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        # only process requests
        if not messageIsRequest:
            return

        requestInfo = self._helpers.analyzeRequest(currentRequest)
        timestamp = datetime.now()
        self.stdout.println("Intercepting message at:", timestamp.isoformat())
        headers = requestInfo.getHeaders()

        self.stdout.println( \
        "Original Headers:" + \
        "----------------------------------------------" + \
        headers + \
        "----------------------------------------------\n\n")

        headers = list(headers) #it's a Java arraylist; get a python list
        r = re.compile("^hmac")
        eHmac = [e for e in headers if r.match(e)]
        if not eHmac:
            return
        else:
            # print old hmac
            self.stdout.println("Old %s" % eHmac[0])
            
        # remove old hmac in the headers
        headers = [x for x in headers if "hamc: " not in x]

        bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        bodyStr = self._helpers.bytesToString(bodyBytes)

        self.stdout.println("To recalcualte HMAC by calling createHmac")
        hamc_sha256 = self.createHmac(bodyStr)

        self.stdout.println("New hmac: %s" % hamc_sha256)
        headers.append('hmac: %s' % hamc_sha256)

        self.stdout.println( \
        "Updated Headers:" + \
        "----------------------------------------------" + \
        headers + \
        "----------------------------------------------\n\n")

        newMessage = self._helpers.buildHttpMessage(headers, bodyStr)

        self.stdout.println( \
        "Sending modified message: " + \
        "----------------------------------------------" + \
        self._helpers.bytesToString(newMessage) + \
        "----------------------------------------------\n\n")

        currentRequest.setRequest(newMessage)
        return


    def createHmac(self, message):
        msg = bytes(message).encode('utf-8')
        # convert secret from Base64 to Bytes
        secret = bytes(base64.standard_b64decode(BurpExtender.secret))
        b64_hash = base64.b64encode(hmac.new(secret, msg, digestmod=hashlib.sha256).digest())
        return b64_hash
