from burp import IBurpExtender
from burp import ISessionHandlingAction
from java.io import PrintWriter
from hashlib import sha256

class BurpExtender(IBurpExtender, ISessionHandlingAction):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # save the helpers for later
        self.helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Digest Header Updater")
        callbacks.registerSessionHandlingAction(self)
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stdout.println("setup done")
    #
    # Implement ISessionHandlingAction
    #

    def getActionName(self):
        # Name of the extender that shows in drop down 
        # Project Options >>> Sessions >>> Session handeling Rules >>> Add >>> Rule Actions >>> Add >>> invoke a Burp extension
        return "update Digest Header"

    def performAction(self, current_request, macro_items):
        requestInfo = self.helpers.analyzeRequest(current_request)
        headers = requestInfo.getHeaders()
        msgBody = current_request.getRequest()[requestInfo.getBodyOffset():]

        hash_fn = sha256()
        hash_fn.update(self.helpers.bytesToString(msgBody))
        for i in range(0,len(headers)):
            # The name of the header is Digest in this case
            if "Digest" in headers[i]:
                self._stdout.println(headers[i])
                # The Header format required in this case was Digest: SHA-256=WPcGJcyXIHvDahSAOygppemjgR6AsLPrSkO8W7S90M4=
                # This can be modified as required
                headers[i] = "Digest: SHA-256="+ hash_fn.digest().encode('base64').strip()
                break

        message = self.helpers.buildHttpMessage(headers, msgBody)
        self._stdout.println(self.helpers.bytesToString(message))
        current_request.setRequest(message)

        return
