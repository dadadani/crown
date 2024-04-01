import std/httpcore
import pkg/uva, pkg/uva/tcp, pkg/uva/futurestreams, std/options
import std/uri, std/strformat, std/strutils, std/parseutils
import ../../utils
import std/net
import ../base_tcp
import picohttpparser
import base
import pkg/uva/resolveaddr
from std/httpclient import ProtocolError, HttpRequestError

type Dasfdsfsdfds* = ref object
    future*: Future[void]

type HTTP1Client* = ref object of HTTP1Base
    readComplete*: Dasfdsfsdfds
    busy*: bool

proc removeBusy*(self: HTTP1Client) =
    self.busy = false
    if (not isNil self.readComplete) and (not isNil self.readComplete) and (not self.readComplete.future.finished):
        self.readComplete.future.complete()
        
proc generateHeaders(version: utils.Http1Version, url: Uri, `method`: HttpMethod, headers: HttpHeaders): string =
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

proc bodyReader*(self: HTTP1Client, stream: FutureStream[string], version: int, contentLength: int, alreadyRead = 0) {.async.} =

    if alreadyRead >= contentLength:
        stream.complete()
        if version == 1 and not self.connectionKeepAlive:
            await self.socket.close()
        return

    var read = alreadyRead
    
    while read < contentLength:
        let buffer = await self.socket.recv(contentLength - read, false)
        if buffer.len == 0:
            if contentLength != 0 and read != contentLength:

                stream.fail(newException(HttpRequestError, "Got disconnected while trying to read body."))
                return
            else:
                break
        read += buffer.len
        await stream.write(buffer)
    self.removeBusy()
    stream.complete()
    
    if not self.connectionKeepAlive:
        await self.socket.close()

proc bodyChunkedReader*(self: HTTP1Client, stream: FutureStream[string], version: int, body: sink string = "") {.async.} =
    var decoder: ChunkedDecoder
    decoder.consume_trailer = 1.char
    var bufsz: csize_t
    var pre = false
    var state = -2.int

    while true:
        if not pre and body.len > 0:
            bufsz = body.len.csize_t
            state = decodeChunked(addr decoder, cast[cstring](addr body[0]), addr bufsz)
            pre = true
        else:
            body = await self.socket.recv(BufferSize, false)
            if body.len == 0:
                self.removeBusy()
                stream.fail(newException(HttpRequestError, "Got disconnected while trying to read body."))
                break
            bufsz = body.len.csize_t
            state = decodeChunked(addr decoder, cast[cstring](addr body[0]), addr bufsz)
        
        case state
        of -1:
            self.removeBusy()
            await self.socket.close()
            stream.fail(newException(HttpRequestError, "Invalid chunked encoding"))
        of -2:
            if bufsz > 0:
                body.setLen(bufsz)
                await stream.write(move(body))
        of 0:
            if bufsz > 0:
                body.setLen(bufsz)
                await stream.write(move(body))
            self.removeBusy()
            stream.complete()

            if not self.connectionKeepAlive:
                await self.socket.close()

            return
        else:
            self.removeBusy()
            stream.complete()
            if not self.connectionKeepAlive:
                await self.socket.close()
            # TODO: handle trailers
            return

proc readForever*(self: HTTP1Client, stream: FutureStream[string]) {.async.} =
    while true:
        let buffer = await self.socket.recv(BufferSize, false)
        if buffer.len == 0:
            self.removeBusy()
            stream.complete()
            break
        await stream.write(buffer)       
    self.socket.close()

proc responseReader*(self: HTTP1Client): Future[(string, HttpHeaders, FutureStream[string])] {.async.} =
    var buffer = ""
    var headers: array[MAX_HEADERS, picohttpparser.Header]
    var minorVersion: cint
    var prevbuflen = 0.csize_t
    var msg: cstring
    var msgLen: csize_t
    var headersLen: csize_t
    var status: cint
    var parsed: cint

    while true:
        prevbuflen = buffer.len.csize_t
        
        buffer.add(await self.socket.recv(BufferSize, false))
        if buffer.len == 0:
            raise newException(HttpRequestError, "Got disconnected while trying to read headers.")
        headersLen = csize_t(sizeof(headers) div sizeof(headers[0]))
        parsed = picohttpparser.parseResponse(cast[cstring](addr buffer[0]), buffer.len.csize_t, addr minorVersion, addr status, addr msg, addr msgLen, cast[ptr picohttpparser.Header](addr headers), addr headersLen, prevbuflen)
        if parsed == -2:
            continue
        elif parsed == -1:
            raise newException(HttpRequestError, "Invalid HTTP response")
        else:
            break

    if minorVersion == 0:
        if not self.allowHTTP10:
            raise newException(HttpRequestError, "Response is HTTP/1.0 which is not allowed")
    elif minorVersion == 1:
        if not self.allowHTTP11:
            raise newException(HttpRequestError, "Response is HTTP/1.1 which is not allowed")
    else:
        raise newException(HttpRequestError, "Invalid HTTP version")

    result[1] = newHttpHeaders()
    for i in 0..<headersLen:
        var key = newString(headers[i].nameLen)
        copyMem(addr key[0], headers[i].name, headers[i].nameLen)
        var val = newString(headers[i].valueLen)
        copyMem(addr val[0], headers[i].value, headers[i].valueLen)
        result[1].add(move(key), move(val))

    result[0] = $status & " " & newString(msgLen)
    copyMem(cast[pointer](cast[uint](addr result[0][0])+(uint(result[0].len)-uint(msgLen))), msg, msgLen)

    var alreadyRead = 0
    if parsed < buffer.len:
        buffer = buffer[parsed..buffer.high]
        alreadyRead = buffer.len
    else:
        buffer.setLen(0)

    if result[1].getOrDefault("Connection") == "close":
        self.connectionKeepAlive = false

    result[2] = newFutureStream[string]("HTTP1Client.responseReader")

    if result[1].getOrDefault("Transfer-Encoding").contains("chunked"):
        try:
            asyncCheck self.bodyChunkedReader(result[2], minorVersion, move(buffer))
        except:
            removeBusy(self)
            raise
    elif result[1].getOrDefault("Content-Length") notin ["", "0"]:
        let length = result[1].getOrDefault("Content-Length").parseInt()
        if alreadyRead > 0:
            await result[2].write(move(buffer))
        try:
            asyncCheck self.bodyReader(result[2], minorVersion, length, alreadyRead = alreadyRead)
        except:
            removeBusy(self)
            raise
    elif not result[1].hasKey("Content-Length") and minorVersion == 0:
        if alreadyRead > 0:
            await result[2].write(move(buffer))
        try:
            asyncCheck self.readForever(result[2])
        except:
            removeBusy(self)
            raise
    else:
        result[2].complete()
        self.removeBusy()
            
    
proc sendRequest*(self: HTTP1Client, url: Uri, `method`: HttpMethod, headers: HttpHeaders, body: FutureStream[string] | string = "", contentLength: int = 0, timeout = 5000.uint): Future[(string, HttpHeaders, FutureStream[string])] {.async.} = 
    
    self.busy = true
    try:

        var version: utils.Http1Version
        if self.allowHTTP11:
            version = utils.HttpVersion11
        elif self.allowHTTP10:
            version = utils.HttpVersion10
        else:
            raise newException(HttpRequestError, "No HTTP version allowed")

        var newHeaders: HttpHeaders
        

        block:
            newHeaders = newHttpHeaders()

            if headers != nil:
                if not headers.hasKey("Content-Length"):
                    if contentLength != 0:
                        newHeaders.add("Content-Length", $contentLength)
                    else:
                        when body is string:
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
                    when body is string:
                        if body.len > 0:
                            newHeaders.add("Content-Length", $body.len)
                    else:
                        raise newException(ValueError, "Content-Length must be specified when using FutureStream[string] as body")
        

        if (not newHeaders.hasKey("Connection") or newHeaders.getOrDefault("Connection") == "keep-alive") and version == HttpVersion11:
            self.connectionKeepAlive = true
        else:
            self.connectionKeepAlive = false

        let rawHeader = generateHeaders(version, url, `method`, newHeaders)

        if self.socket.isClosed:
            raise newException(HttpRequestError, "Socket is closed")
        

        await self.socket.send(rawHeader)
        when body is string:
            if body.len > 0:
                await self.socket.send(body)
        else:
            while not body.finished:
                await self.socket.send(await body.read)
        let read = responseReader(self)
        let timeout = await withTimeout(read, timeout)
        if timeout:
            return read.read
        else:
            removeBusy(self)
            await self.socket.close()
            raise newException(TimeoutError, "Timeout while waiting for response")

    except:
        removeBusy(self)
        raise

