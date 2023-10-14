import compile

const
  NGHTTP2_PROTO_VERSION_ID* = "h2"


const
  NGHTTP2_PROTO_VERSION_ID_LEN* = 2


const
  NGHTTP2_PROTO_ALPN* = "\x02h2"


const
  NGHTTP2_PROTO_ALPN_LEN* = (sizeof((NGHTTP2_PROTO_ALPN)) - 1)


const
  NGHTTP2_CLEARTEXT_PROTO_VERSION_ID* = "h2c"


const
  NGHTTP2_CLEARTEXT_PROTO_VERSION_ID_LEN* = 3


const
  NGHTTP2_VERSION_AGE* = 1


type
  Info* {.importc: "nghttp2_info", header: "nghttp2/nghttp2.h", bycopy.} = object
    age* {.importc: "age".}: cint
    versionNum* {.importc: "version_num".}: cint
    versionStr* {.importc: "version_str".}: cstring
    protoStr* {.importc: "proto_str".}: cstring



const
  NGHTTP2_DEFAULT_WEIGHT* = 16


const
  NGHTTP2_MAX_WEIGHT* = 256


const
  NGHTTP2_MIN_WEIGHT* = 1


const
  NGHTTP2_MAX_WINDOW_SIZE* = ((int32)((1'u shl 31) - 1))


const
  NGHTTP2_INITIAL_WINDOW_SIZE* = ((1 shl 16) - 1)


const
  NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE* = ((1 shl 16) - 1)


const
  NGHTTP2_DEFAULT_HEADER_TABLE_SIZE* = (1 shl 12)


const
  NGHTTP2_CLIENT_MAGIC* = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


const
  NGHTTP2_CLIENT_MAGIC_LEN* = 24


const
  NGHTTP2_DEFAULT_MAX_SETTINGS* = 32


type
  Error* {.size: sizeof(cint).} = enum
    NGHTTP2_ERR_FLOODED = -904, NGHTTP2_ERR_BAD_CLIENT_MAGIC = -903,
    NGHTTP2_ERR_CALLBACK_FAILURE = -902, NGHTTP2_ERR_NOMEM = -901,
    NGHTTP2_ERR_FATAL = -900, NGHTTP2_ERR_TOO_MANY_SETTINGS = -537,
    NGHTTP2_ERR_SETTINGS_EXPECTED = -536, NGHTTP2_ERR_CANCEL = -535,
    NGHTTP2_ERR_INTERNAL = -534, NGHTTP2_ERR_REFUSED_STREAM = -533,
    NGHTTP2_ERR_HTTP_MESSAGING = -532, NGHTTP2_ERR_HTTP_HEADER = -531,
    NGHTTP2_ERR_SESSION_CLOSING = -530, NGHTTP2_ERR_DATA_EXIST = -529,
    NGHTTP2_ERR_PUSH_DISABLED = -528,
    NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS = -527, NGHTTP2_ERR_PAUSE = -526,
    NGHTTP2_ERR_INSUFF_BUFSIZE = -525, NGHTTP2_ERR_FLOW_CONTROL = -524,
    NGHTTP2_ERR_HEADER_COMP = -523, NGHTTP2_ERR_FRAME_SIZE_ERROR = -522,
    NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE = -521,
    NGHTTP2_ERR_INVALID_STATE = -519, NGHTTP2_ERR_INVALID_HEADER_BLOCK = -518,
    NGHTTP2_ERR_GOAWAY_ALREADY_SENT = -517,
    NGHTTP2_ERR_START_STREAM_NOT_ALLOWED = -516,
    NGHTTP2_ERR_DEFERRED_DATA_EXIST = -515,
    NGHTTP2_ERR_INVALID_STREAM_STATE = -514,
    NGHTTP2_ERR_INVALID_STREAM_ID = -513, NGHTTP2_ERR_STREAM_SHUT_WR = -512,
    NGHTTP2_ERR_STREAM_CLOSING = -511, NGHTTP2_ERR_STREAM_CLOSED = -510,
    NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE = -509, NGHTTP2_ERR_DEFERRED = -508,
    NGHTTP2_ERR_EOF = -507, NGHTTP2_ERR_INVALID_FRAME = -506,
    NGHTTP2_ERR_PROTO = -505, NGHTTP2_ERR_WOULDBLOCK = -504,
    NGHTTP2_ERR_UNSUPPORTED_VERSION = -503, NGHTTP2_ERR_BUFFER_ERROR = -502,
    NGHTTP2_ERR_INVALID_ARGUMENT = -501



type
  Vec* {.importc: "nghttp2_vec", header: "nghttp2/nghttp2.h", bycopy.} = object
    base* {.importc: "base".}: ptr uint8
    len* {.importc: "len".}: csize_t


type 
  Nghttp2Struct* = object
  RcBuf* = distinct Nghttp2Struct
  Session* = distinct Nghttp2Struct
  SessionCallbacks* = distinct Nghttp2Struct
  Option* = distinct Nghttp2Struct
  Stream* = distinct Nghttp2Struct
  HdDeflater* = distinct Nghttp2Struct
  HdInflater* = distinct Nghttp2Struct

proc rcbufIncref*(rcbuf: ptr Rcbuf) {.cdecl, importc: "nghttp2_rcbuf_incref",
                                      header: "nghttp2/nghttp2.h".}

proc rcbufDecref*(rcbuf: ptr Rcbuf) {.cdecl, importc: "nghttp2_rcbuf_decref",
                                      header: "nghttp2/nghttp2.h".}

proc rcbufGetBuf*(rcbuf: ptr Rcbuf): Vec {.cdecl,
    importc: "nghttp2_rcbuf_get_buf", header: "nghttp2/nghttp2.h".}

proc rcbufIsStatic*(rcbuf: ptr Rcbuf): cint {.cdecl,
    importc: "nghttp2_rcbuf_is_static", header: "nghttp2/nghttp2.h".}

type
  NvFlag* {.size: sizeof(cint).} = enum
    NGHTTP2_NV_FLAG_NONE = 0, NGHTTP2_NV_FLAG_NO_INDEX = 0x01,
    NGHTTP2_NV_FLAG_NO_COPY_NAME = 0x02, NGHTTP2_NV_FLAG_NO_COPY_VALUE = 0x04



type
  Nv* {.importc: "nghttp2_nv", header: "nghttp2/nghttp2.h", bycopy.} = object
    name* {.importc: "name".}: ptr uint8
    value* {.importc: "value".}: ptr uint8
    namelen* {.importc: "namelen".}: csize_t
    valuelen* {.importc: "valuelen".}: csize_t
    flags* {.importc: "flags".}: uint8



type
  FrameType* {.size: sizeof(cint).} = enum
    NGHTTP2_DATA = 0, NGHTTP2_HEADERS = 0x01, NGHTTP2_PRIORITY = 0x02,
    NGHTTP2_RST_STREAM = 0x03, NGHTTP2_SETTINGS = 0x04,
    NGHTTP2_PUSH_PROMISE = 0x05, NGHTTP2_PING = 0x06, NGHTTP2_GOAWAY = 0x07,
    NGHTTP2_WINDOW_UPDATE = 0x08, NGHTTP2_CONTINUATION = 0x09,
    NGHTTP2_ALTSVC = 0x0a, NGHTTP2_ORIGIN = 0x0c, NGHTTP2_PRIORITY_UPDATE = 0x10



type
  Flag* {.size: sizeof(cint).} = enum
    NGHTTP2_FLAG_NONE = 0, NGHTTP2_FLAG_END_STREAM = 0x01,
    NGHTTP2_FLAG_END_HEADERS = 0x04, NGHTTP2_FLAG_PADDED = 0x08,
    NGHTTP2_FLAG_PRIORITY = 0x20

const
  NGHTTP2_FLAG_ACK = NGHTTP2_FLAG_END_STREAM


type
  settingsId* {.size: sizeof(cint).} = enum
    NGHTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x01,
    NGHTTP2_SETTINGS_ENABLE_PUSH = 0x02,
    NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
    NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
    NGHTTP2_SETTINGS_MAX_FRAME_SIZE = 0x05,
    NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x06,
    NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08,
    NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES = 0x09



const
  NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS* = ((1'u shl 31) - 1)


type
  ErrorCode* {.size: sizeof(cint).} = enum
    NGHTTP2_NO_ERROR = 0x00, NGHTTP2_PROTOCOL_ERROR = 0x01,
    NGHTTP2_INTERNAL_ERROR = 0x02, NGHTTP2_FLOW_CONTROL_ERROR = 0x03,
    NGHTTP2_SETTINGS_TIMEOUT = 0x04, NGHTTP2_STREAM_CLOSED = 0x05,
    NGHTTP2_FRAME_SIZE_ERROR = 0x06, NGHTTP2_REFUSED_STREAM = 0x07,
    NGHTTP2_CANCEL = 0x08, NGHTTP2_COMPRESSION_ERROR = 0x09,
    NGHTTP2_CONNECT_ERROR = 0x0a, NGHTTP2_ENHANCE_YOUR_CALM = 0x0b,
    NGHTTP2_INADEQUATE_SECURITY = 0x0c, NGHTTP2_HTTP_1_1_REQUIRED = 0x0d



type
  FrameHd* {.importc: "nghttp2_frame_hd", header: "nghttp2/nghttp2.h", bycopy.} = object
    length* {.importc: "length".}: csize_t
    streamId* {.importc: "stream_id".}: int32
    `type`* {.importc: "type".}: uint8
    flags* {.importc: "flags".}: uint8
    reserved* {.importc: "reserved".}: uint8



type
  DataSource* {.importc: "nghttp2_data_source", header: "nghttp2/nghttp2.h", bycopy,
                union.} = object
    fd* {.importc: "fd".}: cint
    `ptr`* {.importc: "ptr".}: pointer



type
  DataFlag* {.size: sizeof(cint).} = enum
    NGHTTP2_DATA_FLAG_NONE = 0, NGHTTP2_DATA_FLAG_EOF = 0x01,
    NGHTTP2_DATA_FLAG_NO_END_STREAM = 0x02, NGHTTP2_DATA_FLAG_NO_COPY = 0x04



type
  DataSourceReadCallback* = proc (session: ptr Session; streamId: int32;
                                  buf: ptr uint8; length: csize_t;
                                  dataFlags: ptr uint32; source: ptr DataSource;
                                  userData: pointer): cint {.cdecl.}


type
  DataProvider* {.importc: "nghttp2_data_provider", header: "nghttp2/nghttp2.h", bycopy.} = object
    source* {.importc: "source".}: DataSource
    readCallback* {.importc: "read_callback".}: DataSourceReadCallback



type
  Data* {.importc: "nghttp2_data", header: "nghttp2/nghttp2.h", bycopy.} = object
    hd* {.importc: "hd".}: FrameHd
    padlen* {.importc: "padlen".}: csize_t



type
  HeadersCategory* {.size: sizeof(cint).} = enum
    NGHTTP2_HCAT_REQUEST = 0, NGHTTP2_HCAT_RESPONSE = 1,
    NGHTTP2_HCAT_PUSH_RESPONSE = 2, NGHTTP2_HCAT_HEADERS = 3



type
  PrioritySpec* {.importc: "nghttp2_priority_spec", header: "nghttp2/nghttp2.h", bycopy.} = object
    streamId* {.importc: "stream_id".}: int32
    weight* {.importc: "weight".}: int32
    exclusive* {.importc: "exclusive".}: uint8



type
  Headers* {.importc: "nghttp2_headers", header: "nghttp2/nghttp2.h", bycopy.} = object
    hd* {.importc: "hd".}: FrameHd
    padlen* {.importc: "padlen".}: csize_t
    priSpec* {.importc: "pri_spec".}: PrioritySpec
    nva* {.importc: "nva".}: ptr Nv
    nvlen* {.importc: "nvlen".}: csize_t
    cat* {.importc: "cat".}: HeadersCategory



type
  Priority* {.importc: "nghttp2_priority", header: "nghttp2/nghttp2.h", bycopy.} = object
    hd* {.importc: "hd".}: FrameHd
    priSpec* {.importc: "pri_spec".}: PrioritySpec



type
  RstStream* {.importc: "nghttp2_rst_stream", header: "nghttp2/nghttp2.h", bycopy.} = object
    hd* {.importc: "hd".}: FrameHd
    errorCode* {.importc: "error_code".}: uint32



type
  settingsEntry* {.importc: "nghttp2_settings_entry", header: "nghttp2/nghttp2.h",
                   bycopy.} = object
    settingsId* {.importc: "settings_id".}: int32
    value* {.importc: "value".}: uint32



type
  settings* {.importc: "nghttp2_settings", header: "nghttp2/nghttp2.h", bycopy.} = object
    hd* {.importc: "hd".}: FrameHd
    niv* {.importc: "niv".}: csize_t
    iv* {.importc: "iv".}: ptr settingsEntry



type
  PushPromise* {.importc: "nghttp2_push_promise", header: "nghttp2/nghttp2.h", bycopy.} = object
    hd* {.importc: "hd".}: FrameHd
    padlen* {.importc: "padlen".}: csize_t
    nva* {.importc: "nva".}: ptr Nv
    nvlen* {.importc: "nvlen".}: csize_t
    promisedStreamId* {.importc: "promised_stream_id".}: int32
    reserved* {.importc: "reserved".}: uint8



type
  Ping* {.importc: "nghttp2_ping", header: "nghttp2/nghttp2.h", bycopy.} = object
    hd* {.importc: "hd".}: FrameHd
    opaqueData* {.importc: "opaque_data".}: array[8, uint8]



type
  Goaway* {.importc: "nghttp2_goaway", header: "nghttp2/nghttp2.h", bycopy.} = object
    hd* {.importc: "hd".}: FrameHd
    lastStreamId* {.importc: "last_stream_id".}: int32
    errorCode* {.importc: "error_code".}: uint32
    opaqueData* {.importc: "opaque_data".}: ptr uint8
    opaqueDataLen* {.importc: "opaque_data_len".}: csize_t
    reserved* {.importc: "reserved".}: uint8



type
  WindowUpdate* {.importc: "nghttp2_window_update", header: "nghttp2/nghttp2.h", bycopy.} = object
    hd* {.importc: "hd".}: FrameHd
    windowSizeIncrement* {.importc: "window_size_increment".}: int32
    reserved* {.importc: "reserved".}: uint8



type
  Extension* {.importc: "nghttp2_extension", header: "nghttp2/nghttp2.h", bycopy.} = object
    hd* {.importc: "hd".}: FrameHd
    payload* {.importc: "payload".}: pointer



type
  Frame* {.importc: "nghttp2_frame", header: "nghttp2/nghttp2.h", bycopy, union.} = object
    hd* {.importc: "hd".}: FrameHd
    data* {.importc: "data".}: Data
    headers* {.importc: "headers".}: Headers
    priority* {.importc: "priority".}: Priority
    rstStream* {.importc: "rst_stream".}: RstStream
    settings* {.importc: "settings".}: settings
    pushPromise* {.importc: "push_promise".}: PushPromise
    ping* {.importc: "ping".}: Ping
    goaway* {.importc: "goaway".}: Goaway
    windowUpdate* {.importc: "window_update".}: WindowUpdate
    ext* {.importc: "ext".}: Extension



type
  SendCallback* = proc (session: ptr Session; data: ptr uint8; length: csize_t;
                        flags: cint; userData: pointer): int {.cdecl.}


type
  SendDataCallback* = proc (session: ptr Session; frame: ptr Frame;
                            framehd: ptr uint8; length: csize_t;
                            source: ptr DataSource; userData: pointer): cint {.
      cdecl.}


type
  RecvCallback* = proc (session: ptr Session; buf: ptr uint8; length: csize_t;
                        flags: cint; userData: pointer): cint {.cdecl.}


type
  OnFrameRecvCallback* = proc (session: ptr Session; frame: ptr Frame;
                               userData: pointer): cint {.cdecl.}


type
  OnInvalidFrameRecvCallback* = proc (session: ptr Session; frame: ptr Frame;
                                      libErrorCode: cint; userData: pointer): cint {.
      cdecl.}


type
  OnDataChunkRecvCallback* = proc (session: ptr Session; flags: uint8;
                                   streamId: int32; data: ptr uint8; len: csize_t;
                                   userData: pointer): cint {.cdecl.}


type
  BeforeFrameSendCallback* = proc (session: ptr Session; frame: ptr Frame;
                                   userData: pointer): cint {.cdecl.}


type
  OnFrameSendCallback* = proc (session: ptr Session; frame: ptr Frame;
                               userData: pointer): cint {.cdecl.}


type
  OnFrameNotSendCallback* = proc (session: ptr Session; frame: ptr Frame;
                                  libErrorCode: cint; userData: pointer): cint {.
      cdecl.}


type
  OnStreamCloseCallback* = proc (session: ptr Session; streamId: int32;
                                 errorCode: uint32; userData: pointer): cint {.
      cdecl.}


type
  OnBeginHeadersCallback* = proc (session: ptr Session; frame: ptr Frame;
                                  userData: pointer): cint {.cdecl.}


type
  OnHeaderCallback* = proc (session: ptr Session; frame: ptr Frame;
                            name: ptr uint8; namelen: csize_t; value: ptr uint8;
                            valuelen: csize_t; flags: uint8; userData: pointer): cint {.
      cdecl.}


type
  OnHeaderCallback2* = proc (session: ptr Session; frame: ptr Frame;
                             name: ptr Rcbuf; value: ptr Rcbuf; flags: uint8;
                             userData: pointer): cint {.cdecl.}


type
  OnInvalidHeaderCallback* = proc (session: ptr Session; frame: ptr Frame;
                                   name: ptr uint8; namelen: csize_t;
                                   value: ptr uint8; valuelen: csize_t;
                                   flags: uint8; userData: pointer): cint {.
      cdecl.}


type
  OnInvalidHeaderCallback2* = proc (session: ptr Session; frame: ptr Frame;
                                    name: ptr Rcbuf; value: ptr Rcbuf;
                                    flags: uint8; userData: pointer): cint {.
      cdecl.}


type
  SelectPaddingCallback* = proc (session: ptr Session; frame: ptr Frame;
                                 maxPayloadlen: csize_t; userData: pointer): cint {.
      cdecl.}


type
  DataSourceReadLengthCallback* = proc (session: ptr Session; frameType: uint8;
                                        streamId: int32;
                                        sessionRemoteWindowSize: int32;
                                        streamRemoteWindowSize: int32;
                                        remoteMaxFrameSize: uint32;
                                        userData: pointer): cint {.cdecl.}


type
  OnBeginFrameCallback* = proc (session: ptr Session; hd: ptr FrameHd;
                                userData: pointer): cint {.cdecl.}


type
  OnExtensionChunkRecvCallback* = proc (session: ptr Session; hd: ptr FrameHd;
                                        data: ptr uint8; len: csize_t;
                                        userData: pointer): cint {.cdecl.}


type
  UnpackExtensionCallback* = proc (session: ptr Session; payload: ptr pointer;
                                   hd: ptr FrameHd; userData: pointer): cint {.
      cdecl.}


type
  PackExtensionCallback* = proc (session: ptr Session; buf: ptr uint8;
                                 len: csize_t; frame: ptr Frame; userData: pointer): cint {.
      cdecl.}


type
  ErrorCallback* = proc (session: ptr Session; msg: cstring; len: csize_t;
                         userData: pointer): cint {.cdecl.}


type
  ErrorCallback2* = proc (session: ptr Session; libErrorCode: cint;
                          msg: cstring; len: csize_t; userData: pointer): cint {.
      cdecl.}


proc sessionCallbacksNew*(callbacksPtr: ptr ptr SessionCallbacks): cint {.cdecl,
    importc: "nghttp2_session_callbacks_new", header: "nghttp2/nghttp2.h".}

proc sessionCallbacksDel*(callbacks: ptr SessionCallbacks) {.cdecl,
    importc: "nghttp2_session_callbacks_del", header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetSendCallback*(cbs: ptr SessionCallbacks;
                                      sendCallback: SendCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_send_callback", header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetRecvCallback*(cbs: ptr SessionCallbacks;
                                      recvCallback: RecvCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_recv_callback", header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnFrameRecvCallback*(cbs: ptr SessionCallbacks;
    onFrameRecvCallback: OnFrameRecvCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_frame_recv_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnInvalidFrameRecvCallback*(cbs: ptr SessionCallbacks;
    onInvalidFrameRecvCallback: OnInvalidFrameRecvCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_invalid_frame_recv_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnDataChunkRecvCallback*(cbs: ptr SessionCallbacks;
    onDataChunkRecvCallback: OnDataChunkRecvCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_data_chunk_recv_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetBeforeFrameSendCallback*(cbs: ptr SessionCallbacks;
    beforeFrameSendCallback: BeforeFrameSendCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_before_frame_send_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnFrameSendCallback*(cbs: ptr SessionCallbacks;
    onFrameSendCallback: OnFrameSendCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_frame_send_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnFrameNotSendCallback*(cbs: ptr SessionCallbacks;
    onFrameNotSendCallback: OnFrameNotSendCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_frame_not_send_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnStreamCloseCallback*(cbs: ptr SessionCallbacks;
    onStreamCloseCallback: OnStreamCloseCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_stream_close_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnBeginHeadersCallback*(cbs: ptr SessionCallbacks;
    onBeginHeadersCallback: OnBeginHeadersCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_begin_headers_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnHeaderCallback*(cbs: ptr SessionCallbacks;
    onHeaderCallback: OnHeaderCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_header_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnHeaderCallback2*(cbs: ptr SessionCallbacks;
    onHeaderCallback2: OnHeaderCallback2) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_header_callback2",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnInvalidHeaderCallback*(cbs: ptr SessionCallbacks;
    onInvalidHeaderCallback: OnInvalidHeaderCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_invalid_header_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnInvalidHeaderCallback2*(cbs: ptr SessionCallbacks;
    onInvalidHeaderCallback2: OnInvalidHeaderCallback2) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_invalid_header_callback2",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetSelectPaddingCallback*(cbs: ptr SessionCallbacks;
    selectPaddingCallback: SelectPaddingCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_select_padding_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetDataSourceReadLengthCallback*(cbs: ptr SessionCallbacks;
    dataSourceReadLengthCallback: DataSourceReadLengthCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_data_source_read_length_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnBeginFrameCallback*(cbs: ptr SessionCallbacks;
    onBeginFrameCallback: OnBeginFrameCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_begin_frame_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetSendDataCallback*(cbs: ptr SessionCallbacks;
    sendDataCallback: SendDataCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_send_data_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetPackExtensionCallback*(cbs: ptr SessionCallbacks;
    packExtensionCallback: PackExtensionCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_pack_extension_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetUnpackExtensionCallback*(cbs: ptr SessionCallbacks;
    unpackExtensionCallback: UnpackExtensionCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_unpack_extension_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetOnExtensionChunkRecvCallback*(cbs: ptr SessionCallbacks;
    onExtensionChunkRecvCallback: OnExtensionChunkRecvCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_on_extension_chunk_recv_callback",
    header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetErrorCallback*(cbs: ptr SessionCallbacks;
                                       errorCallback: ErrorCallback) {.cdecl,
    importc: "nghttp2_session_callbacks_set_error_callback", header: "nghttp2/nghttp2.h".}

proc sessionCallbacksSetErrorCallback2*(cbs: ptr SessionCallbacks;
                                        errorCallback2: ErrorCallback2) {.cdecl,
    importc: "nghttp2_session_callbacks_set_error_callback2",
    header: "nghttp2/nghttp2.h".}

type
  Malloc* = proc (size: csize_t; memUserData: pointer): pointer {.cdecl.}


type
  Free* = proc (`ptr`: pointer; memUserData: pointer) {.cdecl.}


type
  Calloc* = proc (nmemb: csize_t; size: csize_t; memUserData: pointer): pointer {.
      cdecl.}


type
  Realloc* = proc (`ptr`: pointer; size: csize_t; memUserData: pointer): pointer {.
      cdecl.}


type
  Mem* {.importc: "nghttp2_mem", header: "nghttp2/nghttp2.h", bycopy.} = object
    memUserData* {.importc: "mem_user_data".}: pointer
    malloc* {.importc: "malloc".}: Malloc
    free* {.importc: "free".}: Free
    calloc* {.importc: "calloc".}: Calloc
    realloc* {.importc: "realloc".}: Realloc



proc optionNew*(optionPtr: ptr ptr Option): cint {.cdecl,
    importc: "nghttp2_option_new", header: "nghttp2/nghttp2.h".}

proc optionDel*(option: ptr Option) {.cdecl, importc: "nghttp2_option_del",
                                      header: "nghttp2/nghttp2.h".}

proc optionSetNoAutoWindowUpdate*(option: ptr Option; val: cint) {.cdecl,
    importc: "nghttp2_option_set_no_auto_window_update", header: "nghttp2/nghttp2.h".}

proc optionSetPeerMaxConcurrentStreams*(option: ptr Option; val: uint32) {.
    cdecl, importc: "nghttp2_option_set_peer_max_concurrent_streams",
    header: "nghttp2/nghttp2.h".}

proc optionSetNoRecvClientMagic*(option: ptr Option; val: cint) {.cdecl,
    importc: "nghttp2_option_set_no_recv_client_magic", header: "nghttp2/nghttp2.h".}

proc optionSetNoHttpMessaging*(option: ptr Option; val: cint) {.cdecl,
    importc: "nghttp2_option_set_no_http_messaging", header: "nghttp2/nghttp2.h".}

proc optionSetMaxReservedRemoteStreams*(option: ptr Option; val: uint32) {.
    cdecl, importc: "nghttp2_option_set_max_reserved_remote_streams",
    header: "nghttp2/nghttp2.h".}

proc optionSetUserRecvExtensionType*(option: ptr Option; `type`: uint8) {.cdecl,
    importc: "nghttp2_option_set_user_recv_extension_type", header: "nghttp2/nghttp2.h".}

proc optionSetBuiltinRecvExtensionType*(option: ptr Option; `type`: uint8) {.
    cdecl, importc: "nghttp2_option_set_builtin_recv_extension_type",
    header: "nghttp2/nghttp2.h".}

proc optionSetNoAutoPingAck*(option: ptr Option; val: cint) {.cdecl,
    importc: "nghttp2_option_set_no_auto_ping_ack", header: "nghttp2/nghttp2.h".}

proc optionSetMaxSendHeaderBlockLength*(option: ptr Option; val: csize_t) {.cdecl,
    importc: "nghttp2_option_set_max_send_header_block_length",
    header: "nghttp2/nghttp2.h".}

proc optionSetMaxDeflateDynamicTableSize*(option: ptr Option; val: csize_t) {.
    cdecl, importc: "nghttp2_option_set_max_deflate_dynamic_table_size",
    header: "nghttp2/nghttp2.h".}

proc optionSetNoClosedStreams*(option: ptr Option; val: cint) {.cdecl,
    importc: "nghttp2_option_set_no_closed_streams", header: "nghttp2/nghttp2.h".}

proc optionSetMaxOutboundAck*(option: ptr Option; val: csize_t) {.cdecl,
    importc: "nghttp2_option_set_max_outbound_ack", header: "nghttp2/nghttp2.h".}

proc optionSetMaxSettings*(option: ptr Option; val: csize_t) {.cdecl,
    importc: "nghttp2_option_set_max_settings", header: "nghttp2/nghttp2.h".}

proc optionSetServerFallbackRfc7540Priorities*(option: ptr Option; val: cint) {.
    cdecl, importc: "nghttp2_option_set_server_fallback_rfc7540_priorities",
    header: "nghttp2/nghttp2.h".}

proc optionSetNoRfc9113LeadingAndTrailingWsValidation*(option: ptr Option;
    val: cint) {.cdecl, importc: "nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation",
                 header: "nghttp2/nghttp2.h".}

proc sessionClientNew*(sessionPtr: ptr ptr Session;
                       callbacks: ptr SessionCallbacks; userData: pointer): cint {.
    cdecl, importc: "nghttp2_session_client_new", header: "nghttp2/nghttp2.h".}

proc sessionServerNew*(sessionPtr: ptr ptr Session;
                       callbacks: ptr SessionCallbacks; userData: pointer): cint {.
    cdecl, importc: "nghttp2_session_server_new", header: "nghttp2/nghttp2.h".}

proc sessionClientNew2*(sessionPtr: ptr ptr Session;
                        callbacks: ptr SessionCallbacks; userData: pointer;
                        option: ptr Option): cint {.cdecl,
    importc: "nghttp2_session_client_new2", header: "nghttp2/nghttp2.h".}

proc sessionServerNew2*(sessionPtr: ptr ptr Session;
                        callbacks: ptr SessionCallbacks; userData: pointer;
                        option: ptr Option): cint {.cdecl,
    importc: "nghttp2_session_server_new2", header: "nghttp2/nghttp2.h".}

proc sessionClientNew3*(sessionPtr: ptr ptr Session;
                        callbacks: ptr SessionCallbacks; userData: pointer;
                        option: ptr Option; mem: ptr Mem): cint {.cdecl,
    importc: "nghttp2_session_client_new3", header: "nghttp2/nghttp2.h".}

proc sessionServerNew3*(sessionPtr: ptr ptr Session;
                        callbacks: ptr SessionCallbacks; userData: pointer;
                        option: ptr Option; mem: ptr Mem): cint {.cdecl,
    importc: "nghttp2_session_server_new3", header: "nghttp2/nghttp2.h".}

proc sessionDel*(session: ptr Session) {.cdecl, importc: "nghttp2_session_del",
    header: "nghttp2/nghttp2.h".}

proc sessionSend*(session: ptr Session): cint {.cdecl,
    importc: "nghttp2_session_send", header: "nghttp2/nghttp2.h".}

proc sessionMemSend*(session: ptr Session; dataPtr: ptr ptr uint8): cint {.
    cdecl, importc: "nghttp2_session_mem_send", header: "nghttp2/nghttp2.h".}

proc sessionRecv*(session: ptr Session): cint {.cdecl,
    importc: "nghttp2_session_recv", header: "nghttp2/nghttp2.h".}

proc sessionMemRecv*(session: ptr Session; `in`: ptr uint8; inlen: csize_t): cint {.
    cdecl, importc: "nghttp2_session_mem_recv", header: "nghttp2/nghttp2.h".}

proc sessionResumeData*(session: ptr Session; streamId: int32): cint {.cdecl,
    importc: "nghttp2_session_resume_data", header: "nghttp2/nghttp2.h".}

proc sessionWantRead*(session: ptr Session): cint {.cdecl,
    importc: "nghttp2_session_want_read", header: "nghttp2/nghttp2.h".}

proc sessionWantWrite*(session: ptr Session): cint {.cdecl,
    importc: "nghttp2_session_want_write", header: "nghttp2/nghttp2.h".}

proc sessionGetStreamUserData*(session: ptr Session; streamId: int32): pointer {.
    cdecl, importc: "nghttp2_session_get_stream_user_data", header: "nghttp2/nghttp2.h".}

proc sessionSetStreamUserData*(session: ptr Session; streamId: int32;
                               streamUserData: pointer): cint {.cdecl,
    importc: "nghttp2_session_set_stream_user_data", header: "nghttp2/nghttp2.h".}

proc sessionSetUserData*(session: ptr Session; userData: pointer) {.cdecl,
    importc: "nghttp2_session_set_user_data", header: "nghttp2/nghttp2.h".}

proc sessionGetOutboundQueueSize*(session: ptr Session): csize_t {.cdecl,
    importc: "nghttp2_session_get_outbound_queue_size", header: "nghttp2/nghttp2.h".}

proc sessionGetStreamEffectiveRecvDataLength*(session: ptr Session;
    streamId: int32): int32 {.cdecl, importc: "nghttp2_session_get_stream_effective_recv_data_length",
                              header: "nghttp2/nghttp2.h".}

proc sessionGetStreamEffectiveLocalWindowSize*(session: ptr Session;
    streamId: int32): int32 {.cdecl, importc: "nghttp2_session_get_stream_effective_local_window_size",
                              header: "nghttp2/nghttp2.h".}

proc sessionGetStreamLocalWindowSize*(session: ptr Session; streamId: int32): int32 {.
    cdecl, importc: "nghttp2_session_get_stream_local_window_size",
    header: "nghttp2/nghttp2.h".}

proc sessionGetEffectiveRecvDataLength*(session: ptr Session): int32 {.cdecl,
    importc: "nghttp2_session_get_effective_recv_data_length",
    header: "nghttp2/nghttp2.h".}

proc sessionGetEffectiveLocalWindowSize*(session: ptr Session): int32 {.cdecl,
    importc: "nghttp2_session_get_effective_local_window_size",
    header: "nghttp2/nghttp2.h".}

proc sessionGetLocalWindowSize*(session: ptr Session): int32 {.cdecl,
    importc: "nghttp2_session_get_local_window_size", header: "nghttp2/nghttp2.h".}

proc sessionGetStreamRemoteWindowSize*(session: ptr Session; streamId: int32): int32 {.
    cdecl, importc: "nghttp2_session_get_stream_remote_window_size",
    header: "nghttp2/nghttp2.h".}

proc sessionGetRemoteWindowSize*(session: ptr Session): int32 {.cdecl,
    importc: "nghttp2_session_get_remote_window_size", header: "nghttp2/nghttp2.h".}

proc sessionGetStreamLocalClose*(session: ptr Session; streamId: int32): cint {.
    cdecl, importc: "nghttp2_session_get_stream_local_close",
    header: "nghttp2/nghttp2.h".}

proc sessionGetStreamRemoteClose*(session: ptr Session; streamId: int32): cint {.
    cdecl, importc: "nghttp2_session_get_stream_remote_close",
    header: "nghttp2/nghttp2.h".}

proc sessionGetHdInflateDynamicTableSize*(session: ptr Session): csize_t {.cdecl,
    importc: "nghttp2_session_get_hd_inflate_dynamic_table_size",
    header: "nghttp2/nghttp2.h".}

proc sessionGetHdDeflateDynamicTableSize*(session: ptr Session): csize_t {.cdecl,
    importc: "nghttp2_session_get_hd_deflate_dynamic_table_size",
    header: "nghttp2/nghttp2.h".}

proc sessionTerminateSession*(session: ptr Session; errorCode: uint32): cint {.
    cdecl, importc: "nghttp2_session_terminate_session", header: "nghttp2/nghttp2.h".}

proc sessionTerminateSession2*(session: ptr Session; lastStreamId: int32;
                               errorCode: uint32): cint {.cdecl,
    importc: "nghttp2_session_terminate_session2", header: "nghttp2/nghttp2.h".}

proc submitShutdownNotice*(session: ptr Session): cint {.cdecl,
    importc: "nghttp2_submit_shutdown_notice", header: "nghttp2/nghttp2.h".}

proc sessionGetRemoteSettings*(session: ptr Session; id: settingsId): uint32 {.
    cdecl, importc: "nghttp2_session_get_remote_settings", header: "nghttp2/nghttp2.h".}

proc sessionGetLocalSettings*(session: ptr Session; id: settingsId): uint32 {.
    cdecl, importc: "nghttp2_session_get_local_settings", header: "nghttp2/nghttp2.h".}

proc sessionSetNextStreamId*(session: ptr Session; nextStreamId: int32): cint {.
    cdecl, importc: "nghttp2_session_set_next_stream_id", header: "nghttp2/nghttp2.h".}

proc sessionGetNextStreamId*(session: ptr Session): uint32 {.cdecl,
    importc: "nghttp2_session_get_next_stream_id", header: "nghttp2/nghttp2.h".}

proc sessionConsume*(session: ptr Session; streamId: int32; size: csize_t): cint {.
    cdecl, importc: "nghttp2_session_consume", header: "nghttp2/nghttp2.h".}

proc sessionConsumeConnection*(session: ptr Session; size: csize_t): cint {.cdecl,
    importc: "nghttp2_session_consume_connection", header: "nghttp2/nghttp2.h".}

proc sessionConsumeStream*(session: ptr Session; streamId: int32; size: csize_t): cint {.
    cdecl, importc: "nghttp2_session_consume_stream", header: "nghttp2/nghttp2.h".}

proc sessionChangeStreamPriority*(session: ptr Session; streamId: int32;
                                  priSpec: ptr PrioritySpec): cint {.cdecl,
    importc: "nghttp2_session_change_stream_priority", header: "nghttp2/nghttp2.h".}

proc sessionCreateIdleStream*(session: ptr Session; streamId: int32;
                              priSpec: ptr PrioritySpec): cint {.cdecl,
    importc: "nghttp2_session_create_idle_stream", header: "nghttp2/nghttp2.h".}

proc sessionUpgrade*(session: ptr Session; settingsPayload: ptr uint8;
                     settingsPayloadlen: csize_t; streamUserData: pointer): cint {.
    cdecl, importc: "nghttp2_session_upgrade", header: "nghttp2/nghttp2.h".}

proc sessionUpgrade2*(session: ptr Session; settingsPayload: ptr uint8;
                      settingsPayloadlen: csize_t; headRequest: cint;
                      streamUserData: pointer): cint {.cdecl,
    importc: "nghttp2_session_upgrade2", header: "nghttp2/nghttp2.h".}

proc packSettingsPayload*(buf: ptr uint8; buflen: csize_t; iv: ptr settingsEntry;
                          niv: csize_t): cint {.cdecl,
    importc: "nghttp2_pack_settings_payload", header: "nghttp2/nghttp2.h".}

proc strerror*(libErrorCode: cint): cstring {.cdecl,
    importc: "nghttp2_strerror", header: "nghttp2/nghttp2.h".}

proc http2Strerror*(errorCode: uint32): cstring {.cdecl,
    importc: "nghttp2_http2_strerror", header: "nghttp2/nghttp2.h".}

proc prioritySpecInit*(priSpec: ptr PrioritySpec; streamId: int32;
                       weight: int32; exclusive: cint) {.cdecl,
    importc: "nghttp2_priority_spec_init", header: "nghttp2/nghttp2.h".}

proc prioritySpecDefaultInit*(priSpec: ptr PrioritySpec) {.cdecl,
    importc: "nghttp2_priority_spec_default_init", header: "nghttp2/nghttp2.h".}

proc prioritySpecCheckDefault*(priSpec: ptr PrioritySpec): cint {.cdecl,
    importc: "nghttp2_priority_spec_check_default", header: "nghttp2/nghttp2.h".}

proc submitRequest*(session: ptr Session; priSpec: ptr PrioritySpec;
                    nva: ptr Nv; nvlen: csize_t; dataPrd: ptr DataProvider;
                    streamUserData: pointer): int32 {.cdecl,
    importc: "nghttp2_submit_request", header: "nghttp2/nghttp2.h".}

proc submitResponse*(session: ptr Session; streamId: int32; nva: ptr Nv;
                     nvlen: csize_t; dataPrd: ptr DataProvider): cint {.cdecl,
    importc: "nghttp2_submit_response", header: "nghttp2/nghttp2.h".}

proc submitTrailer*(session: ptr Session; streamId: int32; nva: ptr Nv;
                    nvlen: csize_t): cint {.cdecl,
    importc: "nghttp2_submit_trailer", header: "nghttp2/nghttp2.h".}

proc submitHeaders*(session: ptr Session; flags: uint8; streamId: int32;
                    priSpec: ptr PrioritySpec; nva: ptr Nv; nvlen: csize_t;
                    streamUserData: pointer): int32 {.cdecl,
    importc: "nghttp2_submit_headers", header: "nghttp2/nghttp2.h".}

proc submitData*(session: ptr Session; flags: uint8; streamId: int32;
                 dataPrd: ptr DataProvider): cint {.cdecl,
    importc: "nghttp2_submit_data", header: "nghttp2/nghttp2.h".}

proc submitPriority*(session: ptr Session; flags: uint8; streamId: int32;
                     priSpec: ptr PrioritySpec): cint {.cdecl,
    importc: "nghttp2_submit_priority", header: "nghttp2/nghttp2.h".}

const
  NGHTTP2_EXTPRI_DEFAULT_URGENCY* = 3


const
  NGHTTP2_EXTPRI_URGENCY_HIGH* = 0


const
  NGHTTP2_EXTPRI_URGENCY_LOW* = 7


const
  NGHTTP2_EXTPRI_URGENCY_LEVELS* = (NGHTTP2_EXTPRI_URGENCY_LOW + 1)


type
  Extpri* {.importc: "nghttp2_extpri", header: "nghttp2/nghttp2.h", bycopy.} = object
    urgency* {.importc: "urgency".}: uint32
    inc* {.importc: "inc".}: cint



proc submitRstStream*(session: ptr Session; flags: uint8; streamId: int32;
                      errorCode: uint32): cint {.cdecl,
    importc: "nghttp2_submit_rst_stream", header: "nghttp2/nghttp2.h".}

proc submitSettings*(session: ptr Session; flags: uint8; iv: ptr settingsEntry;
                     niv: csize_t): cint {.cdecl,
    importc: "nghttp2_submit_settings", header: "nghttp2/nghttp2.h".}

proc submitPushPromise*(session: ptr Session; flags: uint8; streamId: int32;
                        nva: ptr Nv; nvlen: csize_t;
                        promisedStreamUserData: pointer): int32 {.cdecl,
    importc: "nghttp2_submit_push_promise", header: "nghttp2/nghttp2.h".}

proc submitPing*(session: ptr Session; flags: uint8; opaqueData: ptr uint8): cint {.
    cdecl, importc: "nghttp2_submit_ping", header: "nghttp2/nghttp2.h".}

proc submitGoaway*(session: ptr Session; flags: uint8; lastStreamId: int32;
                   errorCode: uint32; opaqueData: ptr uint8;
                   opaqueDataLen: csize_t): cint {.cdecl,
    importc: "nghttp2_submit_goaway", header: "nghttp2/nghttp2.h".}

proc sessionGetLastProcStreamId*(session: ptr Session): int32 {.cdecl,
    importc: "nghttp2_session_get_last_proc_stream_id", header: "nghttp2/nghttp2.h".}

proc sessionCheckRequestAllowed*(session: ptr Session): cint {.cdecl,
    importc: "nghttp2_session_check_request_allowed", header: "nghttp2/nghttp2.h".}

proc sessionCheckServerSession*(session: ptr Session): cint {.cdecl,
    importc: "nghttp2_session_check_server_session", header: "nghttp2/nghttp2.h".}

proc submitWindowUpdate*(session: ptr Session; flags: uint8; streamId: int32;
                         windowSizeIncrement: int32): cint {.cdecl,
    importc: "nghttp2_submit_window_update", header: "nghttp2/nghttp2.h".}

proc sessionSetLocalWindowSize*(session: ptr Session; flags: uint8;
                                streamId: int32; windowSize: int32): cint {.
    cdecl, importc: "nghttp2_session_set_local_window_size", header: "nghttp2/nghttp2.h".}

proc submitExtension*(session: ptr Session; `type`: uint8; flags: uint8;
                      streamId: int32; payload: pointer): cint {.cdecl,
    importc: "nghttp2_submit_extension", header: "nghttp2/nghttp2.h".}

type
  ExtAltsvc* {.importc: "nghttp2_ext_altsvc", header: "nghttp2/nghttp2.h", bycopy.} = object
    origin* {.importc: "origin".}: ptr uint8
    originLen* {.importc: "origin_len".}: csize_t
    fieldValue* {.importc: "field_value".}: ptr uint8
    fieldValueLen* {.importc: "field_value_len".}: csize_t



proc submitAltsvc*(session: ptr Session; flags: uint8; streamId: int32;
                   origin: ptr uint8; originLen: csize_t; fieldValue: ptr uint8;
                   fieldValueLen: csize_t): cint {.cdecl,
    importc: "nghttp2_submit_altsvc", header: "nghttp2/nghttp2.h".}

type
  OriginEntry* {.importc: "nghttp2_origin_entry", header: "nghttp2/nghttp2.h", bycopy.} = object
    origin* {.importc: "origin".}: ptr uint8
    originLen* {.importc: "origin_len".}: csize_t



type
  ExtOrigin* {.importc: "nghttp2_ext_origin", header: "nghttp2/nghttp2.h", bycopy.} = object
    nov* {.importc: "nov".}: csize_t
    ov* {.importc: "ov".}: ptr OriginEntry



proc submitOrigin*(session: ptr Session; flags: uint8; ov: ptr OriginEntry;
                   nov: csize_t): cint {.cdecl, importc: "nghttp2_submit_origin",
                                       header: "nghttp2/nghttp2.h".}

type
  ExtPriorityUpdate* {.importc: "nghttp2_ext_priority_update",
                       header: "nghttp2/nghttp2.h", bycopy.} = object
    streamId* {.importc: "stream_id".}: int32
    fieldValue* {.importc: "field_value".}: ptr uint8
    fieldValueLen* {.importc: "field_value_len".}: csize_t



proc submitPriorityUpdate*(session: ptr Session; flags: uint8; streamId: int32;
                           fieldValue: ptr uint8; fieldValueLen: csize_t): cint {.
    cdecl, importc: "nghttp2_submit_priority_update", header: "nghttp2/nghttp2.h".}

proc sessionChangeExtpriStreamPriority*(session: ptr Session; streamId: int32;
                                        extpri: ptr Extpri;
                                        ignoreClientSignal: cint): cint {.cdecl,
    importc: "nghttp2_session_change_extpri_stream_priority",
    header: "nghttp2/nghttp2.h".}

proc nvCompareName*(lhs: ptr Nv; rhs: ptr Nv): cint {.cdecl,
    importc: "nghttp2_nv_compare_name", header: "nghttp2/nghttp2.h".}

proc selectNextProtocol*(`out`: ptr ptr cuchar; outlen: ptr cuchar;
                         `in`: ptr cuchar; inlen: cuint): cint {.cdecl,
    importc: "nghttp2_select_next_protocol", header: "nghttp2/nghttp2.h".}

proc version*(leastVersion: cint): ptr Info {.cdecl, importc: "nghttp2_version",
    header: "nghttp2/nghttp2.h".}

proc isFatal*(libErrorCode: cint): cint {.cdecl, importc: "nghttp2_is_fatal",
    header: "nghttp2/nghttp2.h".}

proc checkHeaderName*(name: ptr uint8; len: csize_t): cint {.cdecl,
    importc: "nghttp2_check_header_name", header: "nghttp2/nghttp2.h".}

proc checkHeaderValue*(value: ptr uint8; len: csize_t): cint {.cdecl,
    importc: "nghttp2_check_header_value", header: "nghttp2/nghttp2.h".}

proc checkHeaderValueRfc9113*(value: ptr uint8; len: csize_t): cint {.cdecl,
    importc: "nghttp2_check_header_value_rfc9113", header: "nghttp2/nghttp2.h".}

proc checkMethod*(value: ptr uint8; len: csize_t): cint {.cdecl,
    importc: "nghttp2_check_method", header: "nghttp2/nghttp2.h".}

proc checkPath*(value: ptr uint8; len: csize_t): cint {.cdecl,
    importc: "nghttp2_check_path", header: "nghttp2/nghttp2.h".}

proc checkAuthority*(value: ptr uint8; len: csize_t): cint {.cdecl,
    importc: "nghttp2_check_authority", header: "nghttp2/nghttp2.h".}


proc hdDeflateNew*(deflaterPtr: ptr ptr HdDeflater;
                   maxDeflateDynamicTableSize: csize_t): cint {.cdecl,
    importc: "nghttp2_hd_deflate_new", header: "nghttp2/nghttp2.h".}

proc hdDeflateNew2*(deflaterPtr: ptr ptr HdDeflater;
                    maxDeflateDynamicTableSize: csize_t; mem: ptr Mem): cint {.
    cdecl, importc: "nghttp2_hd_deflate_new2", header: "nghttp2/nghttp2.h".}

proc hdDeflateDel*(deflater: ptr HdDeflater) {.cdecl,
    importc: "nghttp2_hd_deflate_del", header: "nghttp2/nghttp2.h".}

proc hdDeflateChangeTableSize*(deflater: ptr HdDeflater;
                               settingsMaxDynamicTableSize: csize_t): cint {.
    cdecl, importc: "nghttp2_hd_deflate_change_table_size", header: "nghttp2/nghttp2.h".}

proc hdDeflateHd*(deflater: ptr HdDeflater; buf: ptr uint8; buflen: csize_t;
                  nva: ptr Nv; nvlen: csize_t): cint {.cdecl,
    importc: "nghttp2_hd_deflate_hd", header: "nghttp2/nghttp2.h".}

proc hdDeflateHdVec*(deflater: ptr HdDeflater; vec: ptr Vec; veclen: csize_t;
                     nva: ptr Nv; nvlen: csize_t): cint {.cdecl,
    importc: "nghttp2_hd_deflate_hd_vec", header: "nghttp2/nghttp2.h".}

proc hdDeflateBound*(deflater: ptr HdDeflater; nva: ptr Nv; nvlen: csize_t): csize_t {.
    cdecl, importc: "nghttp2_hd_deflate_bound", header: "nghttp2/nghttp2.h".}

proc hdDeflateGetNumTableEntries*(deflater: ptr HdDeflater): csize_t {.cdecl,
    importc: "nghttp2_hd_deflate_get_num_table_entries", header: "nghttp2/nghttp2.h".}

proc hdDeflateGetTableEntry*(deflater: ptr HdDeflater; idx: csize_t): ptr Nv {.
    cdecl, importc: "nghttp2_hd_deflate_get_table_entry", header: "nghttp2/nghttp2.h".}

proc hdDeflateGetDynamicTableSize*(deflater: ptr HdDeflater): csize_t {.cdecl,
    importc: "nghttp2_hd_deflate_get_dynamic_table_size", header: "nghttp2/nghttp2.h".}

proc hdDeflateGetMaxDynamicTableSize*(deflater: ptr HdDeflater): csize_t {.cdecl,
    importc: "nghttp2_hd_deflate_get_max_dynamic_table_size",
    header: "nghttp2/nghttp2.h".}

proc hdInflateNew*(inflaterPtr: ptr ptr HdInflater): cint {.cdecl,
    importc: "nghttp2_hd_inflate_new", header: "nghttp2/nghttp2.h".}

proc hdInflateNew2*(inflaterPtr: ptr ptr HdInflater; mem: ptr Mem): cint {.
    cdecl, importc: "nghttp2_hd_inflate_new2", header: "nghttp2/nghttp2.h".}

proc hdInflateDel*(inflater: ptr HdInflater) {.cdecl,
    importc: "nghttp2_hd_inflate_del", header: "nghttp2/nghttp2.h".}

proc hdInflateChangeTableSize*(inflater: ptr HdInflater;
                               settingsMaxDynamicTableSize: csize_t): cint {.
    cdecl, importc: "nghttp2_hd_inflate_change_table_size", header: "nghttp2/nghttp2.h".}

type
  HdInflateFlag* {.size: sizeof(cint).} = enum
    NGHTTP2_HD_INFLATE_NONE = 0, NGHTTP2_HD_INFLATE_FINAL = 0x01,
    NGHTTP2_HD_INFLATE_EMIT = 0x02



proc hdInflateHd*(inflater: ptr HdInflater; nvOut: ptr Nv;
                  inflateFlags: ptr cint; `in`: ptr uint8; inlen: csize_t;
                  inFinal: cint): cint {.cdecl,
    importc: "nghttp2_hd_inflate_hd", header: "nghttp2/nghttp2.h".}

proc hdInflateHd2*(inflater: ptr HdInflater; nvOut: ptr Nv;
                   inflateFlags: ptr cint; `in`: ptr uint8; inlen: csize_t;
                   inFinal: cint): cint {.cdecl,
    importc: "nghttp2_hd_inflate_hd2", header: "nghttp2/nghttp2.h".}

proc hdInflateEndHeaders*(inflater: ptr HdInflater): cint {.cdecl,
    importc: "nghttp2_hd_inflate_end_headers", header: "nghttp2/nghttp2.h".}

proc hdInflateGetNumTableEntries*(inflater: ptr HdInflater): csize_t {.cdecl,
    importc: "nghttp2_hd_inflate_get_num_table_entries", header: "nghttp2/nghttp2.h".}

proc hdInflateGetTableEntry*(inflater: ptr HdInflater; idx: csize_t): ptr Nv {.
    cdecl, importc: "nghttp2_hd_inflate_get_table_entry", header: "nghttp2/nghttp2.h".}

proc hdInflateGetDynamicTableSize*(inflater: ptr HdInflater): csize_t {.cdecl,
    importc: "nghttp2_hd_inflate_get_dynamic_table_size", header: "nghttp2/nghttp2.h".}

proc hdInflateGetMaxDynamicTableSize*(inflater: ptr HdInflater): csize_t {.cdecl,
    importc: "nghttp2_hd_inflate_get_max_dynamic_table_size",
    header: "nghttp2/nghttp2.h".}

proc sessionFindStream*(session: ptr Session; streamId: int32): ptr Stream {.
    cdecl, importc: "nghttp2_session_find_stream", header: "nghttp2/nghttp2.h".}

type
  StreamProtoState* {.size: sizeof(cint).} = enum
    NGHTTP2_STREAM_STATE_IDLE = 1, NGHTTP2_STREAM_STATE_OPEN,
    NGHTTP2_STREAM_STATE_RESERVED_LOCAL, NGHTTP2_STREAM_STATE_RESERVED_REMOTE,
    NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL,
    NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE, NGHTTP2_STREAM_STATE_CLOSED



proc streamGetState*(stream: ptr Stream): StreamProtoState {.cdecl,
    importc: "nghttp2_stream_get_state", header: "nghttp2/nghttp2.h".}

proc sessionGetRootStream*(session: ptr Session): ptr Stream {.cdecl,
    importc: "nghttp2_session_get_root_stream", header: "nghttp2/nghttp2.h".}

proc streamGetParent*(stream: ptr Stream): ptr Stream {.cdecl,
    importc: "nghttp2_stream_get_parent", header: "nghttp2/nghttp2.h".}
proc streamGetStreamId*(stream: ptr Stream): int32 {.cdecl,
    importc: "nghttp2_stream_get_stream_id", header: "nghttp2/nghttp2.h".}

proc streamGetNextSibling*(stream: ptr Stream): ptr Stream {.cdecl,
    importc: "nghttp2_stream_get_next_sibling", header: "nghttp2/nghttp2.h".}

proc streamGetPreviousSibling*(stream: ptr Stream): ptr Stream {.cdecl,
    importc: "nghttp2_stream_get_previous_sibling", header: "nghttp2/nghttp2.h".}

proc streamGetFirstChild*(stream: ptr Stream): ptr Stream {.cdecl,
    importc: "nghttp2_stream_get_first_child", header: "nghttp2/nghttp2.h".}

proc streamGetWeight*(stream: ptr Stream): int32 {.cdecl,
    importc: "nghttp2_stream_get_weight", header: "nghttp2/nghttp2.h".}

proc streamGetSumDependencyWeight*(stream: ptr Stream): int32 {.cdecl,
    importc: "nghttp2_stream_get_sum_dependency_weight", header: "nghttp2/nghttp2.h".}
