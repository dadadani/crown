#[import private/transports/http2/nghttp2
import uva, uva/tcp, std/tables, std/net
import std/deques
import std/uri
import openssl
import private/transports/base_tcp



type 
  StreamData* = ref object
    data: seq[uint8]
    headers: Table[string, string]
    waiter: Future[Response]

  Request* = object
    headers: seq[Nv]
    waiter: Future[Response]

  Response* = object
    headers: Table[string, string]
    data: seq[uint8]

  HTTP2Base* = ref object
    session: ptr nghttp2.Session
    transport: HttpTcpStream
    streamData: Table[int, StreamData]
    maxStreams: int = 10 # it will be increased by the SETTINGS frame
    writingPaused: bool
    connectionLost: bool 
    pendingWrite: Deque[Request] 



proc flush(self: HTTP2Base) {.async.} =
    while self.pendingWrite.len > 0 and len(self.streamData) < self.maxStreams:
        let req = self.pendingWrite.popFirst()
        
        let streamid = submitRequest(self.session, nil, addr req.headers[0], csize_t(req.headers.len), nil, cast[pointer](self))
        if streamid < 0:
            raise newException(Defect, "Failed to submit request" & $nghttp2.Error(streamid))

        self.streamData[streamid] = StreamData(waiter: req.waiter)



    while self.session.sessionWantWrite() > 0 and not self.writingPaused:
        var buffer: ptr uint8
        let len = self.session.sessionMemSend(addr buffer)
      
        await self.transport.send(buffer, len)

proc updateSettings*(self: HTTP2Base) = 
    self.maxStreams = min(int(self.session.sessionGetLocalSettings(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)), int(self.session.sessionGetRemoteSettings(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)))

    

proc receiveWorker*(self: HTTP2Base) {.async.} = 
    while true:
        echo "lenlen: ", self.streamData.len
        var buffer = await self.transport.recv(65535, false)
        echo "Received ", buffer.len, " bytes, isClosed: ", self.transport.isClosed()
        if buffer.len > 0 and buffer != @[0-] and not self.transport.isClosed():
            echo "Received ", buffer.len, " bytes"
            let processedLen = self.session.sessionMemRecv(cast[ptr uint8](addr buffer[0]), csize_t(buffer.len))
            echo "Processed ", processedLen, " bytes"
            await self.flush()
        else:
            echo "Received 0 bytes"
            break
        #var buffer = create(UncheckedArray[uint8], 4096)
        #echo "Waiting for data..."
        #var read = await self.transport.recvInto(buffer, 4096)
        #echo "Received ", read, " bytes"

proc onFrameRcv(session: ptr Session; frame: ptr Frame;
                               userData: pointer): cint {.cdecl.} =
    let session = cast[HTTP2Base](userData)
                        
    if (frame.hd.flags and uint8(NGHTTP2_FLAG_END_HEADERS)) != 0:  
        echo "End headers"

    if (frame.hd.flags and uint8(NGHTTP2_FLAG_END_STREAM)) != 0:
        if frame.hd.`type` in [uint8(NGHTTP2_DATA), uint8(NGHTTP2_HEADERS)]:    
            echo "End stream"
            session.streamData[frame.hd.streamId].waiter.complete(Response(headers: session.streamData[frame.hd.streamId].headers, data: session.streamData[frame.hd.streamId].data))
    
    case frame.hd.`type`
    #if frame.hd.`type` == uint8(NGHTTP2_GOAWAY):
    of uint8(NGHTTP2_GOAWAY):
        echo "Goaway"
        let goaway = frame.goaway
        echo "error code: ", goaway.errorCode
    of uint8(NGHTTP2_SETTINGS):
        session.updateSettings()
    else:
        discard

    
        

    discard

proc onFrameSend(session: ptr Session; frame: ptr Frame;
                               userData: pointer): cint {.cdecl.} =
    echo "Frame sent"
    discard

proc onDataChunkRecv(session: ptr Session; flags: uint8;
                                   streamId: int32; data: ptr uint8; len: csize_t;
                                   userData: pointer): cint {.cdecl.} =     
    var session = cast[HTTP2Base](userData)

    echo "lenlen2: ", session.streamData.len

    if session.streamData.hasKey(streamId):
        var dataSeq = newSeq[uint8](len)
        copyMem(addr dataSeq[0], data, len)
        session.streamData[streamId].data.add(dataSeq)
        echo "Data chunk received for stream ", streamId
    else:
        echo "Data chunk received for unknown stream"

    session = nil

proc onStreamClose(session: ptr Session; streamId: int32;
                                          errorCode: uint32; userData: pointer): cint {.cdecl.} =
    let session = cast[HTTP2Base](userData)

    echo "Stream closed"

    let code = ErrorCode(errorCode)

    echo "Stream ", streamId, " closed with error code ", code

   # echo "Headers: ", session.streamData[streamId].headers
    


    discard

proc onBeginHeaders(session: ptr Session; frame: ptr Frame;
                                  userData: pointer): cint {.cdecl.} =
    echo "Begin headers"
    discard

proc onHeader(session: ptr Session; frame: ptr Frame;
                            name: ptr uint8; namelen: csize_t; value: ptr uint8;
                            valuelen: csize_t; flags: uint8; userData: pointer): cint {.
      cdecl.} =
    let session = cast[HTTP2Base](userData)

    var nameStr = newString(namelen)
    copyMem(addr nameStr[0], name, namelen)

    var valueStr = newString(valuelen)
    if valueStr.len > 0:
        copyMem(addr valueStr[0], value, valuelen)
    echo "Header: ", nameStr, ": ", valueStr
    session.streamData[frame.hd.streamId].headers[nameStr] = valueStr

    discard



proc MakeNV(name: string, value: string): Nv =
    return Nv(name: cast[ptr uint8](addr name[0]), namelen: csize_t(name.len), value: cast[ptr uint8](addr value[0]), valuelen: csize_t(value.len), flags: uint8(NGHTTP2_NV_FLAG_NONE))

proc nextProtoSelectCallback(s: SslPtr; out_proto: cstring; outlen: cstring; in_proto: cstring; inlen: cuint; arg: pointer): cint {.cdecl.} =
    let err = selectNextProtocol(cast[ptr ptr cuchar](addr out_proto), cast[ptr cuchar](outlen), cast[ptr cuchar](in_proto), inlen)
    if err != 0:
        return SSL_TLSEXT_ERR_NOACK
    return SSL_TLSEXT_ERR_OK

proc createSSL(sslctx: SslCtx): SslPtr =
    result = SSL_new(sslctx)
    if isNil result:
        raise newException(Defect, "Failed to create SSL object" & $ERR_error_string(culong(ERR_peek_last_error()), nil))

proc createSSLCTX(): SslCtx =
    result = SSL_CTX_new(SSLv23_client_method())
    if isNil result:
        raise newException(Defect, "Failed to create SSL context" & $ERR_error_string(culong(ERR_peek_last_error()), nil))
    #SSL_CTX_set_next_proto_select_cb(result, nextProtoSelectCallback, nil)

    if getOpenSSLVersion() > 0x10002000:
        discard SSL_CTX_set_alpn_protos(result, NGHTTP2_PROTO_ALPN, NGHTTP2_PROTO_ALPN_LEN);

    discard

proc makeRequest(self: HTTP2Base, url: string|Uri, headers: Table[string, string] = initTable[string, string]()): Future[Response] = 

    var uri: Uri

    when url.typedesc is Uri:
        uri = url
    else:
        parseUri(url, uri)
    

    var req = Request(headers: @[
        MakeNV(":method", "GET"),
        MakeNV(":scheme", uri.scheme),
        MakeNV(":authority", uri.hostname & ":" & uri.port),
        MakeNV(":path", uri.path & "?" & uri.query)
    ], waiter: newFuture[Response]())

    for k, v in headers:
        req.headers.add(MakeNV(k, v))
    
    echo "path: ", uri.path & "?" & uri.query

    self.pendingWrite.addLast(req)

    asyncCheck self.flush()   

    return req.waiter
    #[
    let headers = [
        MakeNV(":method", "GET"),
        MakeNV(":scheme", "https"),
        MakeNV(":authority", "localhost:5000"),
        MakeNV(":path", "/")
    ]

        
    let streamid = submitRequest(self.session, nil, cast[ptr Nv](addr headers), csize_t(headers.len), nil, cast[pointer](self))
    if streamid < 0:
        raise newException(Defect, "Failed to submit request" & $nghttp2.Error(streamid))

    self.streamData[streamid] = StreamData()

    await flush(self)]#
proc malloc(size: csize_t; memUserData: pointer): pointer {.cdecl.} =
    echo "malloc of size ", size
    result = alloc(size)


proc free(`ptr`: pointer; memUserData: pointer) {.cdecl.} =
    if `ptr` != nil:
        echo "free"
        dealloc(`ptr`)

proc realloc(`ptr`: pointer; size: csize_t; memUserData: pointer): pointer {.cdecl.} =
    echo "realloc of size ", size
    result = realloc(`ptr`, size)

proc calloc(nmemb: csize_t; size: csize_t; memUserData: pointer): pointer {.cdecl.} =
    echo "calloc of size ", nmemb * size
    return alloc0(nmemb * size)

proc createHTTP2(host: string, port: Port): Future[HTTP2Base] {.async.} =
    result = HTTP2Base()
    result.transport = HttpTcpStream()
    #result.transport = newAsyncSocket(buffered=false)
    var sslctx = newContext(verifyMode = CVerifyNone)

    var res = SSL_CTX_set_alpn_protos(sslctx.context, cstring("\x02h2"), cuint(3))
    if res != 0:
        raise newException(Defect, "Failed to set ALPN protocols: " & $ERR_error_string(culong(ERR_peek_last_error()), nil))

    wrapSSL(result.transport, sslctx)



    await result.transport.connect(host, port)

    asyncCheck receiveWorker(result)

    var callbacks: ptr SessionCallbacks
    var options: ptr Option
    var rv = optionNew(addr options)
    if rv != 0:
        raise newException(Defect, "Failed to create options" & $nghttp2.Error(rv))

    optionSetNoHttpMessaging(options, 1)

    discard sessionCallbacksNew(addr callbacks)
    sessionCallbacksSetOnFrameRecvCallback(callbacks, onFrameRcv)
    sessionCallbacksSetOnFrameSendCallback(callbacks, onFrameSend)
    sessionCallbacksSetOnDataChunkRecvCallback(callbacks, onDataChunkRecv)
    sessionCallbacksSetOnStreamCloseCallback(callbacks, onStreamClose)
    sessionCallbacksSetOnBeginHeadersCallback(callbacks, onBeginHeaders)
    sessionCallbacksSetOnHeaderCallback(callbacks, onHeader)

    var memconf = Mem(
        malloc: malloc,
        free: free,
        realloc: realloc,
        calloc: calloc 
    )

    rv = sessionClientNew3(addr result.session, callbacks, cast[pointer](result), options, addr memconf)
    
    if rv != 0:
        raise newException(Defect, "Failed to create session" & $nghttp2.Error(rv))

    sessionCallbacksDel(callbacks)
    var settings: array[2, settingsEntry] = [
        settingsEntry(settingsId: int32(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS), value: uint32(result.maxStreams)),
        settingsEntry(settingsId: int32(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE), value: 65535) 
    ]
    rv = submitSettings(result.session, uint8(NGHTTP2_FLAG_NONE), cast[ptr settingsEntry](addr settings), 2)
    if rv != 0:
        raise newException(Defect, "Failed to submit settings" & $nghttp2.Error(rv))
    await result.flush()


    


let f = waitFor createHTTP2("localhost", 5000.Port)

proc runn() {.async.} =
    let req = await f.makeRequest("https://localhost:5000/") 
    echo cast[string](req.data)


asyncCheck runn()

runForever()
]#
