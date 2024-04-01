import nghttp2
import std/tables, std/deques
import pkg/uva, ../base_tcp, pkg/uva/futurestreams, std/net
import std/openssl
import std/uri
import std/httpclient
import base
import std/importutils
import std/options
import std/streams, std/strutils

proc malloc(size: csize_t; memUserData: pointer): pointer {.cdecl.} =
    return alloc(size)

proc free(`ptr`: pointer; memUserData: pointer) {.cdecl.} =
    if `ptr` != nil:
        dealloc(`ptr`)

proc realloc(`ptr`: pointer; size: csize_t; memUserData: pointer): pointer {.cdecl.} =
    return realloc(`ptr`, size)

proc calloc(nmemb: csize_t; size: csize_t; memUserData: pointer): pointer {.cdecl.} =
    return alloc0(nmemb * size)

const MEMCONF = Mem(
        malloc: malloc,
        free: free,
        realloc: realloc,
        calloc: calloc 
)

type 
  HTTP2Client* = ref object of HTTP2Base
      pendingWrite: Deque[Request] 

proc connectionLost*(self: HTTP2Client) {.async.} =
    privateAccess(HTTP2Base)
    echo "connectionLost"

    if not isNil self.goAwayWaiter:
        self.goAwayWaiter.complete(uint32(NGHTTP2_NO_ERROR))
        self.goAwayWaiter = nil

    await self.transport.close()

    while self.pendingWrite.len > 0:
        echo "pop fail"
        let e = self.pendingWrite.popFirst()
        if (not isNil e.dataProvider) and (not e.dataProvider.waiter.finished):
            e.dataProvider.waiter.fail(newException(ProtocolError, "Connection lost"))
        elif not e.waiter.finished:
            e.waiter.fail(newException(ProtocolError, "Connection lost"))
    
    for k, v in self.streamData:
        echo "streamdata: ", k
        if (not isNil v.dataProvider) and (not v.dataProvider.waiter.finished):
            v.dataProvider.waiter.fail(newException(ProtocolError, "Connection lost"))
        elif not v.waiter.finished:
            v.waiter.fail(newException(ProtocolError, "Connection lost"))
        else:
            v.data.fail(newException(ProtocolError, "Connection lost"))

    #for k, v in self.streamData:



    
proc DataProviderReader(session: ptr Session; streamId: int32;
                                  buf: ptr uint8; length: csize_t;
                                  dataFlags: ptr uint32; source: ptr DataSource;
                                  userData: pointer): int {.cdecl.} =
    echo "Data provider reader: main"
    let holder = cast[StreamRcv](source.`ptr`)
    case holder.variant
    of 1:
        echo "Data provider reader: fd1"
        let holder = cast[StreamRcvStream](source.`ptr`)
        let stream = holder.stream
        if stream.finished:
            dataFlags[] = uint32(NGHTTP2_DATA_FLAG_EOF)
            holder.waiter.complete()

            return 0
        if stream.len > 0:
            let (ok, data) = stream.tryRead()
            assert ok

            echo "max length: ", length
            if csize_t(data.len) > length:
                echo "too much data"
                stream.writeFirst(data[length..data.high])
                copyMem(buf, addr data[0], length)
                result = int(length)
            else:
                copyMem(buf, addr data[0], data.len)
                result = data.len
            
            if stream.finished:
                dataFlags[] = uint32(NGHTTP2_DATA_FLAG_EOF)
                holder.waiter.complete()
        else:
            echo "Waiting for data: deferred"
            holder.isResumed = false
            holder.streamId = streamId
            return int(NGHTTP2_ERR_DEFERRED)
    of 2:
        echo "Data provider reader: fd2"
        let holder = cast[StreamRcvData](source.`ptr`)
        let stream = holder.data
        result = readData(stream, addr buf, int(length))
        if stream.atEnd:
            echo "At end"
            dataFlags[] = uint32(NGHTTP2_DATA_FLAG_EOF)
            holder.waiter.complete()
    else:
        discard
            
proc write(self: HTTP2Client) {.async.} =
    privateAccess(HTTP2Base)
    while self.session.session.sessionWantWrite() > 0 and not self.writingPaused:
        echo "Want write2"
        var buffer: ptr uint8
        let len = self.session.session.sessionMemSend(addr buffer)
        if len < 0:
            raise newException(Defect, "Failed to get send buffer" & $nghttp2.Error(len))
        await self.transport.send(buffer, len)

proc flush(self: HTTP2Client) {.async.} =
    privateAccess(HTTP2Base)

    
    echo "Flushing"
    while self.pendingWrite.len > 0 and len(self.streamData) < self.maxStreams:
        echo "Sending request"
        let req = self.pendingWrite.popFirst()

        var streamid: cint
        var holder: StreamRcv
        proc readDataStreamCallback(future: FutureStream[string]) =
            privateAccess(HTTP2Base)

            echo "Data stream callback"
            if not holder.StreamRcvStream.isResumed:
                let error = sessionResumeData(self.session.session, holder.StreamRcvStream.streamId)
                if error != 0:
                    echo "Error: ", $nghttp2.Error(error)
                holder.StreamRcvStream.isResumed = true
                echo "isclosed: ", self.transport.isClosed
                asyncCheck write(self)

        var dataProvider: DataProvider
        dataProvider.readCallback = DataProviderReader
        if not isNil req.dataProvider:
            holder = req.dataProvider
            dataProvider.source.`ptr` = cast[pointer](req.dataProvider)
            if req.dataProvider.variant == 1:
                req.dataProvider.StreamRcvStream.stream.callback = readDataStreamCallback
            
        echo "Submitting request"
        streamid = submitRequest(self.session.session, nil, addr req.headers[0], csize_t(req.headers.len), (if not isNil dataProvider.source.`ptr`: addr dataProvider else: nil), cast[pointer](self))
        if streamid < 0:
            raise newException(Defect, "Failed to submit request" & $nghttp2.Error(streamid))
        echo "Submitted request with streamid: ", streamid
        self.streamData[streamid] = StreamData(waiter: req.waiter, data: newFutureStream[string]("http2.data"), dataProvider: if not isNil req.dataProvider: req.dataProvider else: nil)


    await write(self)


proc cancelRequest*(self: HTTP2Client, streamId: int32) {.async.} =
    privateAccess(HTTP2Base)
    if not self.streamData.hasKey(streamId):
        return

    let error = self.session.session.submitRstStream(0, streamId, uint32(NGHTTP2_CANCEL))
    if error != 0:
        raise newException(HttpRequestError, "Error submitting RST_STREAM: " & $error)

    await self.flush()

proc worker(self: HTTP2Client) {.async.} =
    privateAccess(HTTP2Base)
    while not self.transport.isClosed:
        echo "read"
        let data = await self.transport.recv(BufferSize, false)
        if data.len == 0:
            echo "Connection closed"
            break
        echo "memrecv"
        if self.session.session == nil:
            echo "Session is nil"
            quit(1)
        let rv = sessionMemRecv(self.session.session, cast[ptr uint8](addr data[0]), data.len.csize_t)
        if rv < 0:
            echo "Error sessionemercv: ", $nghttp2.Error(rv)
            await self.terminate(NGHTTP2_INTERNAL_ERROR)
            await self.flush()
            return

    await connectionLost(self)

proc onFrameRcv(session: ptr Session; frame: ptr Frame;
                               userData: pointer): cint {.cdecl.} =
    let session = cast[HTTP2Base](userData)
    privateAccess(HTTP2Base)              
    if (frame.hd.flags and uint8(NGHTTP2_FLAG_END_HEADERS)) != 0:  
        echo "End headers"

    if (frame.hd.flags and uint8(NGHTTP2_FLAG_END_STREAM)) != 0:
        if frame.hd.`type` in [uint8(NGHTTP2_DATA), uint8(NGHTTP2_HEADERS)]:    
            echo "End stream"
            #session.streamData[frame.hd.streamId].waiter.complete(Response(headers: session.streamData[frame.hd.streamId].headers, data: session.streamData[frame.hd.streamId].data))
    
    case frame.hd.`type`
    #if frame.hd.`type` == uint8(NGHTTP2_GOAWAY):
    of uint8(NGHTTP2_GOAWAY):  
        session.goawayError = newException(ProtocolError, "GOAWAY received: " & $ErrorCode(frame.goaway.errorCode)) 
        discard
    of uint8(NGHTTP2_SETTINGS):
        session.updateSettings()
    else:
        discard

    
        

    discard

proc onFrameSend(session: ptr Session; frame: ptr Frame;
                               userData: pointer): cint {.cdecl.} =
    let session = cast[HTTP2Base](userData)
    privateAccess(HTTP2Base)

    case frame.hd.`type`
    of uint8(NGHTTP2_GOAWAY):
        if not isNil session.goAwayWaiter:
            session.goAwayWaiter.complete(frame.goaway.errorCode)
            session.goAwayWaiter = nil
        session.goawayError = newException(ProtocolError, "GOAWAY: " & $ErrorCode(frame.goaway.errorCode))
    else:
        discard
    echo "Frame sent"

proc onDataChunkRecv(session: ptr Session; flags: uint8;
                                   streamId: int32; data: ptr uint8; len: csize_t;
                                   userData: pointer): cint {.cdecl.} =     
    var session = cast[HTTP2Base](userData)
    privateAccess(HTTP2Base)

    if streamId in session.streamData:
        if not session.streamData[streamId].waiter.finished:
            session.streamData[streamId].waiter.complete((move(session.streamData[streamId].headers), session.streamData[streamId].data))

        var dataSeq = newString(len)
        copyMem(addr dataSeq[0], data, len)
        asyncCheck session.streamData[streamId].data.write(move(dataSeq))
    else:
        echo "Data chunk received for unknown stream"

    session = nil

proc onStreamClose(session: ptr Session; streamId: int32;
                                          errorCode: uint32; userData: pointer): cint {.cdecl.} =
    let session = cast[HTTP2Base](userData)
    privateAccess(HTTP2Base)
    if streamId in session.streamData:
        let data = move(session.streamData[streamId])
        session.streamData.del(streamId)

        if not data.waiter.finished:
            if errorCode == uint32(NGHTTP2_NO_ERROR):
                data.data.complete()
                data.waiter.complete((move(data.headers), move(data.data)))
            else:
                let error = newException(ProtocolError, "Stream failed: " & $ErrorCode(errorCode))
                data.data.fail(error)
                data.waiter.fail(error)
        else:
            if errorCode == uint32(NGHTTP2_NO_ERROR):
                data.data.complete()
            else:
                echo "Stream failed: ", $ErrorCode(errorCode)
                let error = newException(ProtocolError, "Stream failed: " & $ErrorCode(errorCode))
                if (not isNil data.dataProvider) and (not data.dataProvider.waiter.finished):
                    data.dataProvider.waiter.fail(error)
                elif not data.waiter.finished:
                    data.waiter.fail(error)
                else:
                    data.data.fail(error)


   # echo "Headers: ", session.streamData[streamId].headers
    


    

proc onBeginHeaders(session: ptr Session; frame: ptr Frame;
                                  userData: pointer): cint {.cdecl.} =
    let session = cast[HTTP2Base](userData)
    privateAccess(HTTP2Base)
    echo "Begin headers"
    if frame.hd.streamId in session.streamData:
        session.streamData[frame.hd.streamId].headers = newHttpHeaders()

proc onHeader(session: ptr Session; frame: ptr Frame;
                            name: ptr uint8; namelen: csize_t; value: ptr uint8;
                            valuelen: csize_t; flags: uint8; userData: pointer): cint {.
      cdecl.} =
    let session = cast[HTTP2Base](userData)
    privateAccess(HTTP2Base)

    if frame.hd.streamId in session.streamData:
        echo "streamid: ", frame.hd.streamId
        var nameStr = newString(namelen)
        copyMem(addr nameStr[0], name, namelen)

        var valueStr = newString(valuelen)
        if valueStr.len > 0:
            copyMem(addr valueStr[0], value, valuelen)
        echo "name: ", nameStr, " value: ", valueStr
        session.streamData[frame.hd.streamId].headers.add(move(nameStr), move(valueStr))



proc sendRequest*(self: HTTP2Client, url: Uri, `method`: HttpMethod, headers: HttpHeaders = newHttpHeaders(), body: FutureStream[string] | string = "", timeout = 5000.uint): Future[(HttpHeaders, FutureStream[string])] {.async.} = 
    privateAccess(HTTP2Base)

    if self.goawayError != nil:
        raise self.goawayError

    echo "authority: ", url.hostname & ":" & url.port
    
    let path = (if url.path.len > 0: url.path else: "/") 

    var req = Request(headers: @[
        MakeNV(":method", $`method`),
        MakeNV(":scheme", url.scheme),
        MakeNV(":authority", url.hostname & ":" & url.port),
        MakeNV(":path", path & "?" & url.query)
    ], waiter: newFuture[(HttpHeaders, FutureStream[string])]())


    when body is string:
        if body.len > 0:
            req.dataProvider = StreamRcvData(variant: 2, data: newStringStream(body), waiter: newFuture[void]("http2.dataProvider.waiter"))
            #req.data = some(body)
            if not headers.hasKey("Content-Length"):
                req.headers.add(MakeNV("Content-Length", $body.len))
    elif body is FutureStream[string]:
        req.dataProvider = StreamRcvStream(variant: 1, stream: body, isResumed: true, waiter: newFuture[void]("http2.dataProvider.waiter"))

        #req.dataStream = some(body)

    for k, v in headers:
        if k.startsWith(":"):
            raise newException(ValueError, "Header name cannot start with ':'")
        req.headers.add(MakeNV(k, v))
    
    echo "path: ", url.path & "?" & url.query

    self.pendingWrite.addLast(req)

    await self.flush()   

    if not isNil req.dataProvider:
        echo "Waiting for data to be sent: makrequest"
        await req.dataProvider.waiter

    echo "Waiting for response"

    let resp = await withTimeout(req.waiter, timeout)
    if resp:
        return req.waiter.read
    else:
        raise newException(TimeoutError, "Request timed out")

proc createHTTP2*(connection: HttpTcpStream): Future[HTTP2Client] {.async.} =
    result = HTTP2Client()
    privateAccess(HTTP2Base)
    result.transport = connection
    #result.transport = newAsyncSocket(buffered=false)
    #var sslctx = newContext(verifyMode = CVerifyNone)

    #var res = SSL_CTX_set_alpn_protos(sslctx.context, cstring(NGHTTP2_PROTO_ALPN), cuint(len(NGHTTP2_PROTO_ALPN)))
    #if res != 0:
     #   raise newException(Defect, "Failed to set ALPN protocols: " & $ERR_error_string(culong(ERR_peek_last_error()), nil))

    #wrapSSL(result.transport, sslctx)

    #await result.transport.connect(host, port)

   # var alpnc: cstring
   # var alpnLen: cuint
   # privateAccess(HttpTcpStream)
   # SSL_get0_alpn_selected(result.transport.sslHandle, addr alpnc, addr alpnLen)
   # var alpn = newString(alpnLen)
   # copyMem(addr alpn[0], alpnc, alpnLen)
   # if alpn != "h2":
   #     raise newException(ProtocolError, "Failed to negotiate ALPN protocol: " & alpn)
    asyncCheck result.worker()

    echo "Creating session"

    var callbacks: ptr SessionCallbacks
    var options: ptr nghttp2.Option
    var rv = optionNew(addr options)
    if rv != 0:
        raise newException(Defect, "Failed to create options" & $nghttp2.Error(rv))

    #optionSetNoHttpMessaging(options, 1)

    discard sessionCallbacksNew(addr callbacks)
    sessionCallbacksSetOnFrameRecvCallback(callbacks, onFrameRcv)
    sessionCallbacksSetOnFrameSendCallback(callbacks, onFrameSend)
    sessionCallbacksSetOnDataChunkRecvCallback(callbacks, onDataChunkRecv)
    sessionCallbacksSetOnStreamCloseCallback(callbacks, onStreamClose)
    sessionCallbacksSetOnBeginHeadersCallback(callbacks, onBeginHeaders)
    sessionCallbacksSetOnHeaderCallback(callbacks, onHeader)

    echo "Creating session2"
    rv = sessionClientNew3(addr result.session.session, callbacks, cast[pointer](result), options, addr MEMCONF)
    
    if rv != 0:
        raise newException(Defect, "Failed to create session" & $nghttp2.Error(rv))
    echo "Created session3"
    sessionCallbacksDel(callbacks)
    var settings: array[2, settingsEntry] = [
        settingsEntry(settingsId: int32(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS), value: uint32(result.maxStreams)),
        settingsEntry(settingsId: int32(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE), value: 65535) 
    ]
    echo "Submitting settings"
    result.settingsOk = false

    rv = submitSettings(result.session.session, uint8(NGHTTP2_FLAG_NONE), cast[ptr settingsEntry](addr settings), 2)
    if rv != 0:
        raise newException(Defect, "Failed to submit settings" & $nghttp2.Error(rv))
    echo "Submitted settings"
    await result.flush()

proc writeAsync(fut: FutureStream[string]) {.async.} =
   # await sleepAsync(1000)
    #await sleepAsync(5000)

    echo "Writing first"
    await fut.write("""{"chat_id":                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      397112340,               """)
    #await sleepAsync(5000)
    echo "Writing second"
    await fut.write(""" "text":"test"}""")
    fut.complete()
#[
proc reqtest(ht: HTTP2Client) {.async.} =
    #let fut = newFutureStream[string]("testdev")
    #asyncCheck writeAsync(fut)
    let headers = newHttpHeaders()
    headers.add("Content-Type", "application/json")
    let rs = await ht.sendRequest(parseUri("https://localhost:5000/"), headers)
    

    while true:
        echo await rs[1].read()
        if rs[1].finished:
            break
    echo "donex "
    privateAccess(HTTP2Base)
    GC_ref(ht)
    await ht.transport.close()
    echo "closed"
proc run() {.async.} =
    echo "Running"
    let ht = await createHTTP2("localhost", 5000.Port)
    await reqtest(ht)
    #asyncCheck reqtest(ht)
    echo "Created HTTP2 client"
when isMainModule:
    waitFor run()
    #runForever()]#