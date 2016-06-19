require 'java'
require 'json'
java_import 'burp.IBurpExtender'
java_import 'burp.IHttpRequestResponse'
java_import 'burp.IHttpService'
java_import 'burp.ISessionHandlingAction'

class BurpExtender
  include IBurpExtender, ISessionHandlingAction

  def registerExtenderCallbacks(callbacks)
  
    # set our extension name
    callbacks.setExtensionName("Header Injector")

    #Register for Scanner Callbacks
    callbacks.registerSessionHandlingAction(self)
    # obtain our output and error streams
    @stdout = java.io.PrintWriter.new(callbacks.getStdout(), true)
    @stderr = java.io.PrintWriter.new(callbacks.getStderr(), true)
    
    # write a message to our output stream
    @stdout.println("Header Injector")

    #Obtain an extension to the helpers object
    @helpers = callbacks.getHelpers()

    #Keep a reference to the callbacks
    @callbacks = callbacks
  end

  def performAction(baseRequestResponse, macroItems)
    #This analyses the request that we're going to modify
    request_info = @helpers.analyzeRequest(baseRequestResponse)
    #This gets the first response from a macro item... should work for the basic case
    macro_response_info = @helpers.analyzeResponse(macroItems[0].getResponse())
    @stdout.println("Starting up")
    
    #Extract the JWT token from the macro response
    macro_msg = macroItems[0].getResponse()
    macro_body_offset = macro_response_info.getBodyOffset()
    macro_body = macro_msg[macro_body_offset..-1]
    macro_body_string = @helpers.bytesToString(macro_body)
    jwt_token = JSON.parse(macro_body_string)
    jwt = jwt_token["jwt"]


    #Get the headers from our base request
    headers = request_info.getHeaders()
    #we need a ref for the existing authorisation header if any to delete
    auth_to_delete = ''
    #So headers is an ArrayList so no ruby delete methods first iterate over and get our header
    headers.each do |head|
      if head =~ /Authorization: JWT/
        auth_to_delete = head
      end
    end
    #then remove the header if it exists 
    headers.remove(auth_to_delete)

    #Add in our new authorization header
    headers.add('Authorization: JWT ' + jwt)
    #We need to get the body to add to our headers which is what the next three lines do
    msg = baseRequestResponse.getRequest()
    body_offset = request_info.getBodyOffset()
    body = msg[body_offset..-1]

    #Now we can create our new message with the headers and body that we need
    new_message = @helpers.buildHttpMessage(headers, body)
    #Lets just log something so we know it's doing something
    @stdout.println("Changed a message")
    #Set our Request to be the modified version from our code.
    baseRequestResponse.setRequest(new_message)
  end

  def getActionName()
    return "Sample Header Injector"
  end
end