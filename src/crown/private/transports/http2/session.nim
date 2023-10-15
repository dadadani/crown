import nghttp2
import std/tables, std/deques
import std/asyncdispatch, std/asyncstreams, std/asyncnet, std/net
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
    transport: AsyncSocket
    streamData: Table[int, StreamData]
    maxStreams: int
    writingPaused: bool
    connectionLost: bool 

  HTTP2Client* = ref object of HTTP2Base
      pendingWrite: Deque[Request] 


proc createHTTP2(host: string, port: Port): Future[HTTP2Base] {.async.} =
    result = HTTP2Base()


    result.transport = newAsyncSocket(buffered=false)
    var sslctx = newContext(verifyMode = CVerifyNone)

    var res = SSL_CTX_set_alpn_protos(sslctx.context, cstring("\x02h2"), cuint(3))
    if res != 0:
        raise newException(Defect, "Failed to set ALPN protocols: " & $ERR_error_string(culong(ERR_peek_last_error()), nil))
        
    wrapSocket(sslctx, result.transport)

    await result.transport.connect(host, port)

    #[asyncCheck receiveWorker(result)

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
]#