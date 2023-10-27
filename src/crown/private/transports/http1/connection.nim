import std/httpcore
import std/asyncdispatch, std/asyncstreams
import std/asyncnet, std/options
import std/uri, std/strformat, std/strutils, std/parseutils
import ../../utils

import std/asyncfile

from std/httpclient import ProtocolError, HttpRequestError

type HTTP1Base* = object of RootObj
    allowHTTP09*: bool
    allowHTTP10*: bool
    allowHTTP11*: bool
    allowUpgradeToHTTP2*: bool
    socket*: AsyncSocket

type HTTP1Client* = object of HTTP1Base

proc generateHeaders(version: utils.Http1Version, url: Uri, `method`: HttpMethod, headers: HttpHeaders): string =
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
    
    result.add(httpNewLine)

proc forceRead*(self: AsyncSocket, size: int) {.async.} =
    var read = 0
    while true:
        let buffer = await self.recv(size - read)
        if buffer.len == 0:
            raise newException(HttpRequestError, "Server terminated connection prematurely")
        read += buffer.len
        if read == size:
            break

proc streamWriterChunked*(self: HTTP1Client, stream: FutureStream[string], version: Http1Version, connectionKeepAlive: bool) {.async.} =
    while true:
        var chunkSize = 0
        var chunkSizeStr = await self.socket.recvLine()
        var i = 0
        if chunkSizeStr == "":
            raise newException(HttpRequestError, "Server terminated connection prematurely")
        while i < chunkSizeStr.len:
            case chunkSizeStr[i]
            of '0'..'9':
                chunkSize = chunkSize shl 4 or (ord(chunkSizeStr[i]) - ord('0'))
            of 'a'..'f':
                chunkSize = chunkSize shl 4 or (ord(chunkSizeStr[i]) - ord('a') + 10)
            of 'A'..'F':
                chunkSize = chunkSize shl 4 or (ord(chunkSizeStr[i]) - ord('A') + 10)
            of ';':
                # http://tools.ietf.org/html/rfc2616#section-3.6.1
                # We don't care about chunk-extensions.
                break
            else:
                raise newException(HttpRequestError, "Invalid chunk size")
            inc(i)
        if chunkSize <= 0:
            await self.socket.forceRead(2)
            stream.complete()
            break
        
        block:
            var read = 0
            while read < chunkSize:
                var buffer = newString(chunkSize - read)
                let readb = await self.socket.recvInto(addr buffer[0], chunkSize - read)
                if readb == 0:
                    raise newException(HttpRequestError, "Server terminated connection prematurely")
                read += buffer.len
                buffer.setLen(readb)
                await stream.write(move(buffer))
        
        await self.socket.forceRead(2)


            

proc streamWriter*(self: HTTP1Client, stream: FutureStream[string], version: Http1Version, connectionKeepAlive: bool, contentLength: int = 0, alreadyRead = 0) {.async.} =
    let bufferSize = if contentLength != 0: min(contentLength, TCP_BUFFER_SIZE) else: TCP_BUFFER_SIZE
    var read = alreadyRead
    let art = openAsync("art.bin", fmWrite)
    while read < contentLength:
        var buffer = newString(bufferSize)
        let readb = await self.socket.recvInto(addr buffer[0], bufferSize)
        if readb == 0:
            if contentLength != 0 and read != contentLength:
                stream.fail(newException(HttpRequestError, "Got disconnected while trying to read body."))
            break
    
        buffer.setLen(readb)

        
        read += readb
        #echo buffer
        await art.write(move(buffer))
        #await stream.write(move(buffer))

    stream.complete()
    if version == HttpVersion09 or version == HttpVersion10 or (version == HttpVersion11 and not connectionKeepAlive):
        self.socket.close()
    

proc responseHeaderReader*(self: HTTP1Client): Future[(string, HttpHeaders, Option[FutureStream[string]])] {.async.} =
    var line = ""
    var parsedStatus = false
    var version: utils.Http1Version

    while true:
        line = await self.socket.recvLine()
        if line.len == 0:
            raise newException(HttpRequestError, "Got disconnected while trying to read body.")
        
        if line == httpNewLine:
            break

        if not parsedStatus:

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

            parsedStatus = true
            
            if version == HttpVersion09:
                result[2] = some(newFutureStream[string]("HTTP1Client.responseHeaderReader"))
                await result[2].get.write(line)
                asyncCheck self.streamWriter(result[2].get, version, false, alreadyread = line.len)
                return
            
            result[1] = newHttpHeaders()

            # parse status code
            let skip = skipWhitespace(line, 9)
            result[0] = line[8+skip..line.high].strip()

        else:
            var name = ""
            var tok = parseUntil(line, name, ':') 
            
            if tok == 0 or line[tok] != ':':
                raise newException(HttpRequestError, "invalid headers")

            result[1].add(name, line[tok+1..line.high].strip())

            if result[1].len > 100: # todo: change 100 to a constant
                raise newException(HttpRequestError, "too many headers")
        
    
    result[2] = some(newFutureStream[string]("HTTP1Client.responseHeaderReader"))
    if result[1].getOrDefault("Transfer-Encoding") == "chunked":
        asyncCheck self.streamWriterChunked(result[2].get, version, result[1].getOrDefault("Connection") == "keep-alive")
    elif result[1].getOrDefault("Content-Length") != "":
        let length = result[1].getOrDefault("Content-Length").parseInt()
        asyncCheck self.streamWriter(result[2].get, version, result[1].getOrDefault("Connection") == "keep-alive", contentLength = length)

            
    
proc sendRequest*(self: HTTP1Client, url: Uri, `method`: HttpMethod, headers: HttpHeaders, body: FutureStream[string] | string = "", contentLength: int = 0): Future[(string, HttpHeaders, Option[FutureStream[string]])] {.async.} = 
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
        else:
            if contentLength != 0:
                newHeaders.add("Content-Length", $contentLength)
            else:
                if body is string:
                    if body.len > 0:
                        newHeaders.add("Content-Length", $body.len)
                else:
                    raise newException(ValueError, "Content-Length must be specified when using FutureStream[string] as body")
    
    let rawHeader = generateHeaders(version, url, `method`, newHeaders)

    if self.socket.isClosed:
        raise newException(HttpRequestError, "Socket is closed")

    if version == HttpVersion09:
        await self.socket.send(rawHeader)
        return await responseHeaderReader(self)
    else:
        await self.socket.send(rawHeader)
        when body is string:
            if body.len > 0:
                await self.socket.send(body)
        else:
            while not body.finished:
                await self.socket.send(await body.read)
        return await responseHeaderReader(self)


    

    





