import nghttp2
import std/tables, std/deques
import pkg/uva, ../base_tcp, std/asyncstreams, std/net
import std/openssl
import std/uri

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
  StreamData* = ref object
    data: seq[uint8]
    headers: Table[string, string]
    waiter: Future[Response]

  Request* = object
    headers: seq[Nv]
    waiter: Future[Response]

  Response* = object
    headers: Table[string, string]
    data: FutureStream[string]

  HTTP2Base* = ref object of RootObj
    session: ptr nghttp2.Session
    transport: HttpTcpStream
    streamData: Table[int, StreamData]
    maxStreams: int
    writingPaused: bool
    connectionLost: bool 
    settingsOk: bool

  HTTP2Client* = ref object of HTTP2Base
      pendingWrite: Deque[Request] 


proc worker*(self: HTTP2Base) {.async.} =
    while not self.connectionLost:
        discard
    

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
        discard
        #if not isNil session.settingsInitWaiter:
            #session.settingsInitWaiter.complete()
            #session.settingsInitWaiter = nil
        #session.updateSettings()
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



proc createHTTP2(host: string, port: Port): Future[HTTP2Base] {.async.} =
    result = HTTP2Base()
    result.transport = HttpTcpStream()
    #result.transport = newAsyncSocket(buffered=false)
    var sslctx = newContext(verifyMode = CVerifyNone)

    var res = SSL_CTX_set_alpn_protos(sslctx.context, cstring(NGHTTP2_PROTO_ALPN), cuint(NGHTTP2_PROTO_ALPN_LEN))
    if res != 0:
        raise newException(Defect, "Failed to set ALPN protocols: " & $ERR_error_string(culong(ERR_peek_last_error()), nil))

    wrapSSL(result.transport, sslctx)



    await result.transport.connect(host, port)

    #asyncCheck receiveWorker(result)

    var callbacks: ptr SessionCallbacks
    var options: ptr Option
    var rv = optionNew(addr options)
    if rv != 0:
        raise newException(Defect, "Failed to create options" & $nghttp2.Error(rv))

    optionSetNoHttpMessaging(options, 1)

    discard sessionCallbacksNew(addr callbacks)
    #sessionCallbacksSetOnFrameRecvCallback(callbacks, onFrameRcv)
    #sessionCallbacksSetOnFrameSendCallback(callbacks, onFrameSend)
    #sessionCallbacksSetOnDataChunkRecvCallback(callbacks, onDataChunkRecv)
    #sessionCallbacksSetOnStreamCloseCallback(callbacks, onStreamClose)
    #sessionCallbacksSetOnBeginHeadersCallback(callbacks, onBeginHeaders)
    #sessionCallbacksSetOnHeaderCallback(callbacks, onHeader)


    rv = sessionClientNew3(addr result.session, callbacks, cast[pointer](result), options, addr MEMCONF)
    
    if rv != 0:
        raise newException(Defect, "Failed to create session" & $nghttp2.Error(rv))

    sessionCallbacksDel(callbacks)
    var settings: array[2, settingsEntry] = [
        settingsEntry(settingsId: int32(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS), value: uint32(result.maxStreams)),
        settingsEntry(settingsId: int32(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE), value: 65535) 
    ]

    result.settingsOk = false

    rv = submitSettings(result.session, uint8(NGHTTP2_FLAG_NONE), cast[ptr settingsEntry](addr settings), 2)
    if rv != 0:
        raise newException(Defect, "Failed to submit settings" & $nghttp2.Error(rv))
    
    while not result.settingsOk:
        discard