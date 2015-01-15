require 'java'
java_import 'burp.IBurpExtender'
java_import 'burp.IScannerCheck'
java_import 'burp.IScanIssue'
java_import 'burp.IHttpRequestResponse'
java_import 'burp.IHttpService'

class BurpExtender
  include IBurpExtender, IScannerCheck

  def registerExtenderCallbacks(callbacks)
  
    # set our extension name
    callbacks.setExtensionName("Header Checks")

    #Register for Scanner Callbacks
    callbacks.registerScannerCheck(self)
    # obtain our output and error streams
    @stdout = java.io.PrintWriter.new(callbacks.getStdout(), true)
    @stderr = java.io.PrintWriter.new(callbacks.getStderr(), true)
    
    # write a message to our output stream
    @stdout.println("Header Checks")

    #Obtain an extension to the helpers object
    @helpers = callbacks.getHelpers()

    #Keep a reference to the callbacks
    @callbacks = callbacks
  end

  def doPassiveScan(baseRequestResponse)
    service_info = baseRequestResponse.getHttpService()
    host_name = service_info.getHost()
    response_info = @helpers.analyzeResponse(baseRequestResponse.getResponse)
    headers = response_info.getHeaders()
    header_found = false

    headers.each do |header|
      if header.downcase =~ /your_value_here/
          header_found = true
      end
    end
    
    findings = Java::JavaUtil::ArrayList.new

    finding_message = CustomHttpRequestResponse.new
    finding_message.setResponse(baseRequestResponse.getResponse())
    finding_message.setRequest(baseRequestResponse.getRequest())
    finding_message.setHttpService(baseRequestResponse.getHttpService())
    

    unless header_found
      finding = CustomScanIssue.new
      finding.httpMessages=finding_message
      finding.httpService=baseRequestResponse.getHttpService()
      finding.url=@helpers.analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest).getUrl()
      finding.name = "Header Not Set"
      finding.detail = "A header that should be set isn't"
      finding.severity = "Low"
      finding.confidence = "Certain"
      finding.remediation_detail = "Lorem Ipsum"
      finding.issue_background = "Sit Dolor Amet"
      findings.add finding
    end
    return findings
  end

  def consolidateDuplicateIssues(existing_issue, new_issue)
    if existing_issue.getIssueName == new_issue.getIssueName
      return -1
    else
      return 0
    end
  end

end

class CustomScanIssue
  include IScanIssue
  def initialize
  end

  def httpMessages=(httpMessages)
    @httpMessages = httpMessages
  end

  def httpService=(httpService)
    @httpService = httpService
  end

  def name=(name)
    @name = name
  end

  def url=(url)
    @url = url
  end

  def detail=(detail)
    @detail = detail
  end

  def severity=(severity)
    @severity = severity
  end

  def confidence=(confidence)
    @confidence = confidence
  end

  def remediation_detail=(remediation_detail)
    @remediation_detail = remediation_detail
  end

  def issue_background=(issue_background)
    @issue_background = issue_background
  end

  def getUrl
    @url
  end

  def getHttpMessages
    [@httpMessages]
    #Alternate that also works
    #Java::JavaUtil::Arrays.as_list(@httpMessages).to_a
  end

  def getHttpService
    @httpService
  end

  def getRemediationDetail
    @remediation_detail
  end

  def getIssueDetail
    @detail
  end

  def getIssueBackground
    @issue_background
  end

  def getRemediationBackground
    return nil
  end

  def getIssueType
    return 0
  end

  def getIssueName
    @name
  end

  def getSeverity
    @severity
  end

  def getConfidence
    @confidence
  end
end

class CustomHttpRequestResponse
  include IHttpRequestResponse, IHttpService
  def initialize
  end

  def setRequest(request)
    @request = request
  end

  def getRequest()
    return @request
  end

  def setResponse(response)
    @response = response
  end

  def getResponse()
    return @response
  end

  def setComment(comment)
    @comment = comment
  end

  def getComment()
    return @comment
  end

  def setHighlight(highlight)
    @highlight = highlight
  end

  def getHighlight()
    return @highlight
  end

  def setHttpService(httpService)
    @httpService = httpService
  end

  def getHttpService()
    return @httpService
  end
end