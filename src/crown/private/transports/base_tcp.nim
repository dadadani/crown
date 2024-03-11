import pkg/uva, pkg/uva/tcp, pkg/uva/resolveaddr
import std/net

const defineSsl = defined(ssl) or defined(nimdoc)

when defineSsl:
  import std/openssl

  proc sslReadEx*(ssl: SslPtr, buf: cstring, num: cint, readbytes: ptr csize_t): cint{.cdecl,
      dynlib: DLLSSLName, importc: "SSL_read_ex".}

  proc sslPending*(ssl: SslPtr): cint{.cdecl,
      dynlib: DLLSSLName, importc: "SSL_pending".}


type 
  HttpTcpStream* = ref object
    stream: TCP
    useSSL: bool
    when defineSsl:
      sslHandle: SslPtr
      sslContext: SslContext
      bioIn: BIO
      bioOut: BIO
      sslNoShutdown: bool
      #readFuture: Future[void]

#  ReadUnbufferedCallback* = proc (self: HttpTcpStream, data: string)


when defineSsl:

  proc sendPendingSslData(socket: HttpTcpStream) {.async.} =
    let len = bioCtrlPending(socket.bioOut)
    if len > 0:
      var data = newString(len)
      let read = bioRead(socket.bioOut, cast[cstring](addr data[0]), len)
      assert read != 0
      if read < 0:
        raiseSSLError()
      data.setLen(read)
      await socket.stream.send(data)
  

  proc getSslError(socket: HttpTcpStream, err: cint): cint =
    assert socket.useSSL
    assert err < 0
    var ret = SSL_get_error(socket.sslHandle, err.cint)
    case ret
    of SSL_ERROR_ZERO_RETURN:
      raiseSSLError("TLS/SSL connection failed to initiate, socket closed prematurely.")
    of SSL_ERROR_WANT_CONNECT, SSL_ERROR_WANT_ACCEPT:
      return ret
    of SSL_ERROR_WANT_WRITE, SSL_ERROR_WANT_READ:
      return ret
    of SSL_ERROR_WANT_X509_LOOKUP:
      raiseSSLError("Function for x509 lookup has been called.")
    of SSL_ERROR_SYSCALL, SSL_ERROR_SSL:
      socket.sslNoShutdown = true
      raiseSSLError()
    else: raiseSSLError("Unknown Error")

  proc appeaseSsl(socket: HttpTcpStream,
                  sslError: cint): owned(Future[bool]) {.async.} =
    ## Returns `true` if `socket` is still connected, otherwise `false`.
    result = true
    case sslError
    of SSL_ERROR_WANT_WRITE:
      await sendPendingSslData(socket)
    of SSL_ERROR_WANT_READ:
        
          var data = await socket.stream.recvSingle(BufferSize)
          let length = len(data)
          if length > 0:
            let ret = bioWrite(socket.bioIn, cast[cstring](addr data[0]), length.cint)
            if ret < 0:
              raiseSSLError()
          elif length == 0:
            echo "HTTPTCPSTREAM: length == 0"
            # connection not properly closed by remote side or connection dropped
            SSL_set_shutdown(socket.sslHandle, SSL_RECEIVED_SHUTDOWN)
            result = false
        
    else:
      raiseSSLError("Cannot appease SSL.")

  proc sendPendingSslData(socket: HttpTcpStream,
      flags: set[SocketFlag]) {.async.} =
    let len = bioCtrlPending(socket.bioOut)
    if len > 0:
      var data = newString(len)
      let read = bioRead(socket.bioOut, cast[cstring](addr data[0]), len)
      assert read != 0
      if read < 0:
        raiseSSLError()
      data.setLen(read)
      await socket.stream.send(data)

  template sslLoop(socket: HttpTcpStream, op: untyped) =
      var opResult {.inject.} = -1.cint
      while opResult < 0:
        ErrClearError()
        # Call the desired operation.
        opResult = op
        let err =
          if opResult < 0:
            getSslError(socket, opResult.cint)
          else:
            SSL_ERROR_NONE
        # Send any remaining pending SSL data.
        await sendPendingSslData(socket)
        # If the operation failed, try to see if SSL has some data to read
        # or write.
        if opResult < 0:
          let fut = appeaseSsl(socket, err.cint)
          yield fut
          if not fut.read():
            # Socket disconnected.
              opResult = 0.cint
              break
  
  proc wrapSSL*(self: HttpTcpStream, ctx: SslContext) = 
    if self.useSSL:
      raise newException(Defect, "Already using SSL")

    self.useSSL = true
    self.sslContext = ctx
    self.sslHandle = SSL_new(self.sslContext.context)
    if self.sslHandle == nil:
      raiseSSLError()
    
    self.bioIn = bioNew(bioSMem())
    self.bioOut = bioNew(bioSMem())
    sslSetBio(self.sslHandle, self.bioIn, self.bioOut)

    self.sslNoShutdown = false



proc send*(self: HttpTcpStream, data: string) {.async.} =
  if self.useSSL:
    when defineSsl:
      sslLoop(self, sslWrite(self.sslHandle, cast[cstring](addr data[0]), data.len.cint))
      await sendPendingSslData(self)
  else:
    await self.stream.send(data)

proc isClosed*(self: HttpTcpStream): bool =
    return (isNil self.stream) or self.stream.isClosed

proc isActive*(self: HttpTcpStream): bool =
    return (not isNil self.stream) and self.stream.isActive

proc isWritable*(self: HttpTcpStream): bool =
    return (not isNil self.stream) and self.stream.isWritable

proc isReadable*(self: HttpTcpStream): bool =
    return (not isNil self.stream) and self.stream.isReadable

proc close*(self: HttpTcpStream) {.async.} =
  if self.isClosed: return

  defer:
    echo "closing tcp stream"
    await self.stream.close()

  when defineSsl:
    if self.useSSL:
      let res =
        # Don't call SSL_shutdown if the connection has not been fully
        # established, see:
        # https://github.com/openssl/openssl/issues/710#issuecomment-253897666
        if not self.sslNoShutdown and SSL_in_init(self.sslHandle) == 0:
          echo "shutting down ssl"
          ErrClearError()
          SSL_shutdown(self.sslHandle)
        else:
          0
      SSL_free(self.sslHandle)
      if res == 0:
        discard
      elif res != 1:
        raiseSSLError()

proc send*(self: HttpTcpStream, data: pointer, size: int) {.async.} =
  if self.useSSL:
    when defineSsl:
      sslLoop(self, sslWrite(self.sslHandle, cast[cstring](data), size.cint))
      await sendPendingSslData(self)
  else:
    await self.stream.send(data, size)

proc recv*(self: HttpTcpStream, size: int, wait = false): Future[string] {.async.} =
  if self.useSSL:
    when defineSsl:
      var data = newString(size)
      if wait:
        var read = 0
        while read < size:
          sslLoop(self, sslRead(self.sslHandle, cast[cstring](cast[uint](addr (data)[0])+uint(read)), (data.len-read).cint))
          if opResult > 0:
            read += opResult
      else:
        sslLoop(self, sslRead(self.sslHandle, cast[cstring](addr data[0]), size.cint))
        if opResult > 0:
          data.setLen(opResult)
        else:
          return ""
      result = move(data)
  else:
    if wait:
      result = await self.stream.recv(size)
    else:
      result = await self.stream.recvSingle(size)

proc connect*(self: HttpTcpStream, hostname: string, hostnameptr: ptr AddrInfo): Future[void] {.async.} =  
  self.stream = await tcp.dial(hostnameptr)
  when defineSsl:

    if self.useSSL:
      #self.readFuture = newFuture[void]("HttpTcpStream.readFuture")
      if not isIpAddress(hostname):
        discard SSL_set_tlsext_host_name(self.sslHandle, hostname)
      sslSetConnectState(self.sslHandle)

      sslLoop(self, sslDoHandshake(self.sslHandle))

proc connect*(self: HttpTcpStream, host: string, port: Port): Future[void] {.async.} =  
  self.stream = await tcp.dial(host, port)
  when defineSsl:

    if self.useSSL:
      #self.readFuture = newFuture[void]("HttpTcpStream.readFuture")
      if not isIpAddress(host):
        discard SSL_set_tlsext_host_name(self.sslHandle, host)
      sslSetConnectState(self.sslHandle)

      sslLoop(self, sslDoHandshake(self.sslHandle))


when isMainModule:

  proc zaino(self: HttpTcpStream, data: string) =
    echo "zaino: ", data
  proc a() {.async.} =
    echo "creating socket"
    let socket = HttpTcpStream()
    echo "wrapping ssl"
    wrapSSL(socket, newContext(verifyMode = CVerifyNone))
    echo "connecting"
    await socket.connect("localhost", Port(5000), false, zaino)
    echo "connected"
    await socket.send("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    #echo "read1"
    #echo await socket.recv(5907)
  #  await socket.send("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
  
  asyncCheck a()
  runForever()

#[
proc zaino(self: HttpTcpStream, data: string) =
    echo "zaino: ", data

proc a() {.async.} =
  echo "creating socket"
  let socket = HttpTcpStream()
  echo "wrapping ssl"
  echo "connecting"
  await socket.connect("127.0.0.1", Port(8000), false, zaino)
  echo "connected"
  echo "read1"
  await socket.send("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
  echo "read2"
  #echo await socket.recv(5907)

asyncCheck a()
runForever()]#