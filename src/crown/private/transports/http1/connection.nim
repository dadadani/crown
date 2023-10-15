import std/httpcore
import std/asyncdispatch, std/asyncstreams
import std/asyncnet, std/options
import std/uri, std/strformat, std/strutils
import ../../utils

from std/httpclient import ProtocolError, HttpRequestError

type HTTP1Base = object of RootObj
    allowHTTP09*: bool
    allowHTTP10*: bool
    allowHTTP11*: bool
    allowUpgradeToHTTP2*: bool
    socket*: AsyncSocket

type HTTP1Client = object of HTTP1Base

proc generateHeaders(version: utils.Http1Version, url: Uri, `method`: HttpMethod, headers: HttpHeaders, contentLength: int): string =
    if version == utils.HttpVersion09:
        doAssert `method` == HttpGet, "HTTP/0.9 only supports GET method"
        result = "GET "
        result.add(url.path)
        if url.query != "":
            result.add(&"?{url.query}")
        return
    
    result = &"{`method`} "
    result.add(url.path)
    if url.query != "":
        result.add(&"?{url.query}")
    result.add(" " & $version & httpNewLine)
    if not headers.hasKey("Host"):
        if url.port == "":
            result.add(&"Host: {url.hostname}" & httpNewLine)
        else:
            result.add(&"Host: {url.hostname}:{url.port}" & httpNewLine)
    
    if not headers.hasKey("Connection") and version == HttpVersion11:
        result.add("Connection: keep-alive" & httpNewLine)

    if headers != nil:
        for key, val in headers:
            result.add(&"{key}: {val}" & httpNewLine)

proc streamWriter*(self: HTTP1Client, stream: FutureStream[string], contentLength: int = 0, alreadyRead = 0) {.async.} =
    var read = alreadyRead
    while read < contentLength:
        let line = await self.socket.recv(TCP_BUFFER_SIZE)

        if line.len == 0:
            if contentLength != 0 and read < contentLength:
                stream.fail(newException(HttpRequestError, "Got disconnected while trying to read body."))
                break
            else:
                stream.complete()
                break
        
        read += line.len
        
        



proc responseHeaderReader*(self: HTTP1Client): Future[FutureStream[string]] {.async.} =
    
    result = newFutureStream[string]("HTTP1Client.responseHeaderReader")
    var line = ""
    var parsedStatus = false
    while true:
        line = await self.socket.recvLine()
        if line.len == 0:
            raise newException(HttpRequestError, "Got disconnected while trying to read body.")
        
        var version: utils.Http1Version

        if line.startsWith("HTTP/1.1"):
            if not self.allowHTTP11:
                raise newException(HttpRequestError, "HTTP/1.1 is not allowed")
            version = utils.HttpVersion11
        elif line.startsWith("HTTP/1.0"):
            if not self.allowHTTP10:
                raise newException(HttpRequestError, "HTTP/1.0 is not allowed")
            version = utils.HttpVersion10
        else:
            if not self.allowHTTP09:
                raise newException(HttpRequestError, "HTTP/0.9 is not allowed")
            version = utils.HttpVersion09
        
        if version == HttpVersion09:
            await result.write(line)
            asyncCheck self.streamWriter(result, line.len)
            return
        else:
            # parse status code
            let status = line[9..12]
            
        

        
    

    
proc sendRequest*(self: HTTP1Client, url: Uri, `method`: HttpMethod, headers: HttpHeaders, body: FutureStream[string] | string = "", contentLength: int = 0): Future[(HttpCode, HttpHeaders, Option[FutureStream[string]])] {.asynself.} = 
    var version: utils.Http1Version
    if self.allowHTTP11:
        version = utils.HttpVersion11
    elif self.allowHTTP10:
        version = utils.HttpVersion10
    elif self.allowHTTP09:
        version = utils.HttpVersion09
    else:
        raise newException(HttpRequestError, "No HTTP version allowed")

    var newHeaders: HttpHeaders

    if version != HttpVersion09:
        newHeaders = newHttpHeaders()

        if headers != nil:
            if not headers.hasKey("Content-Length"):
                if contentLength != 0:
                    newHeaders.add("Content-Length", $contentLength)
                else:
                    if body is string:
                        if body.len > 0:
                            newHeaders.add("Content-Length", $body.len)
                    else:
                        raise newException(ValueError, "Content-Length must be specified when using FutureStream[string] as body")
            for key, val in headers:
                newHeaders.add(key, val)
    
    let rawHeader = generateHeaders(version, url, `method`, newHeaders, contentLength)

    if self.socket.isClosed:
        raise newException(HttpRequestError, "Socket is closed")

    if version == HttpVersion09:
        await self.socket.send(rawHeader)
    





