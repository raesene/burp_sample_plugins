require 'java'
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
    #This analyses the request that we're going to modift
    request_info = @helpers.analyzeRequest(baseRequestResponse)
    #This gets the first response from a macro item... should work for the basic case
    macro_response_info = @helpers.analyzeResponse(macroItems[0].getResponse())
    @stdout.println("Starting up")
    #In this case we're extracting a header from the macro response to inject int our request
    macro_response_headers = macro_response_info.getHeaders()
    #Burp/Java/JRuby doesn't seem to like dynamic variable assignment to lets declare
    thead = String.new
    #Iterate over our headers looking for the right one
    macro_response_headers.each do |mhead|
      if mhead.downcase =~ /length/
        #if we matche extract the headers value
        thead = mhead
      end
    end

    #Get the headers from our base request
    headers = request_info.getHeaders()
    #Add in this case our sample text
    headers.add('example is' + thead)
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