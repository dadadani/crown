import nghttp2
import std/tables, pkg/uva, pkg/uva/futurestreams, ../base_tcp
from std/httpclient import ProtocolError, HttpRequestError
import std/httpcore
import std/options
import std/streams
type  

  SessionHolder = object
    session*: ptr nghttp2.Session

  StreamRcv* = ref object of RootObj
    waiter*: Future[void]
    variant*: int

  StreamRcvData* = ref object of StreamRcv
    data*: StringStream

  StreamRcvStream* = ref object of StreamRcv
    stream*: FutureStream[string]
    isResumed*: bool
    streamId*: int32

  StreamData* = ref object
    data*: FutureStream[string]
    dataProvider*: StreamRcv
    headers*: HttpHeaders
    waiter*: Future[(HttpHeaders, FutureStream[string])]

  Request* = object
    headers*: seq[Nv]
    dataProvider*: StreamRcv
    waiter*: Future[(HttpHeaders, FutureStream[string])]

  HTTP2Base* = ref object of RootObj
    session: SessionHolder
    transport: HttpTcpStream
    streamData: Table[int, StreamData]
    maxStreams: int = 10
    writingPaused: bool
    settingsOk: bool
    goAwayWaiter: Future[uint32]
    goAwayError: ref ProtocolError

proc `=destroy`(x: SessionHolder) = 
  if x.session != nil:
    x.session.sessionDel()
    dealloc(x.session)

proc updateSettings*(self: HTTP2Base) = 
    self.maxStreams = min(int(self.session.session.sessionGetLocalSettings(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)), int(self.session.session.sessionGetRemoteSettings(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)))

proc terminate*(self: HTTP2Base, error: ErrorCode = NGHTTP2_NO_ERROR) {.async.} = 
    if self.transport.isClosed:
        return

    if not isNil self.goAwayWaiter:
        return

    discard self.session.session.sessionTerminateSession(uint32(error))

    self.goAwayWaiter = newFuture[uint32]("goAwayWaiter")
    discard await self.goAwayWaiter 

proc MakeNV*(name: string, value: string): Nv =
    return Nv(name: cast[ptr uint8](addr name[0]), namelen: csize_t(name.len), value: cast[ptr uint8](addr value[0]), valuelen: csize_t(value.len), flags: uint8(NGHTTP2_NV_FLAG_NONE))
