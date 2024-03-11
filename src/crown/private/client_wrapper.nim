import pkg/uva
import transports/http1/[multiplexer, client]
import transports/http2/[base, client, nghttp2]
import transports/base_tcp
import std/uri, std/httpcore, std/tables, pkg/uva/resolveaddr, pkg/uva/futurestreams, std/options
import std/importutils
import std/openssl, std/net

type ClientWrapper* = ref object
    initWaiter: Future[void]
    allowHTTP10: bool
    allowHTTP11: bool
    allowHTTP2: bool
    http1HostnamePoolSize: int
    http2Client: Table[string, (AddrHolder, Http2Client)]
    http1Multiplexer: Http1Multiplexer



proc portOrDefault(url: Uri): string = 
    if url.port.len > 0:
        return url.port
    if url.scheme == "https":
        return "443"
    return "80"

proc createConnection(self: ClientWrapper, url: Uri, hostnameptr: ptr AddrInfo): Future[HttpTcpStream] {.async.} = 
    result = HttpTcpStream()
    if url.scheme == "https":
        var sslctx = newContext(verifyMode = CVerifyNone)
        if self.allowHTTP2:
            var res = SSL_CTX_set_alpn_protos(sslctx.context, cstring(NGHTTP2_PROTO_ALPN), cuint(len(NGHTTP2_PROTO_ALPN)))
            if res != 0:
                raise newException(OSError, "SSL_CTX_set_alpn_protos failed")
        wrapSSL(result, sslctx)
        await result.connect(url.hostname, hostnameptr)
    else:
        await result.connect(url.hostname, hostnameptr)
        
    #var sslctx = newContext(verifyMode = CVerifyNone)


proc prepareRequest(self: ClientWrapper, url: Uri): Future[(HTTP1Client, Http2Client)] {.async.} = 
    # first, check if we have a client for this hostname
    let keyHostname = url.hostname & ":" & portOrDefault(url)

    if self.http2Client.hasKey(keyHostname):
        let client = self.http2Client[keyHostname][1]
        let hostnameptr = self.http2Client[keyHostname][0].hostname
        privateAccess(HTTP2Base)
        if client.transport.isClosed:
            self.http2Client[keyHostname][1] = await createHTTP2(await createConnection(self, url, hostnameptr))
        result[1] = self.http2Client[keyHostname][1]
    elif self.http1Multiplexer.exists(keyHostname):
        let connection = await self.http1Multiplexer.get(keyHostname)
        if connection[1].socket.isClosed:
            connection[1].socket = await createConnection(self, url, connection[0])
        result[0] = connection[1]
    else:
        let hostnameptr = await resolveAddrPtr(url.hostname, service = portOrDefault(url))
        let connection = await createConnection(self, url, hostnameptr)
        if url.scheme == "https":
            # Check if the ALPN negotiation was successful
            var alpnc: cstring
            var alpnLen: cuint 
            privateAccess(HttpTcpStream)
            SSL_get0_alpn_selected(connection.sslHandle, addr alpnc, addr alpnLen)
            var alpn = ""
            if alpnLen > 0:
                alpn.setLen(alpnLen)
                copyMem(addr alpn[0], alpnc, alpnLen)

            if alpn == "h2":
                privateAccess(HTTP2Base)
                let client = await createHTTP2(await createConnection(self, url, hostnameptr))
                self.http2Client[keyHostname] = (AddrHolder(hostname: hostnameptr), client)
                result[1] = client
            else:
                let httpClient = HTTP1Client(socket: connection, allowHTTP10: self.allowHTTP10, allowHTTP11: self.allowHTTP11)
                httpClient.busy = true
                self.http1Multiplexer.add(keyHostname, hostnameptr, httpClient, self.http1HostnamePoolSize)
                result[0] = httpClient
        else:
            let httpClient = HTTP1Client(socket: connection, allowHTTP10: self.allowHTTP10, allowHTTP11: self.allowHTTP11)
            httpClient.busy = true
            self.http1Multiplexer.add(keyHostname, hostnameptr, httpClient, self.http1HostnamePoolSize)
            result[0] = httpClient
                #let client = 
                #self.http1Multiplexer[keyHostname] = HTTP1Client(socket: connection)
                #return client


proc sendRequest*(self: ClientWrapper, url: Uri, `method`: HttpMethod, headers: HttpHeaders, body: FutureStream[string] | string = "", contentLength: int = 0, timeout = 5000.uint) {.async.} = 
    #if (not isNil self.initWaiter) and self.initWaiter.finished:
    #    await self.initWaiter
    let prep = await prepareRequest(self, url)
    if prep[1] == nil:
        discard await prep[0].sendRequest(url, `method`, headers, body, contentLength, timeout)
    else:
        discard await prep[1].sendRequest(url, `method`, headers, body, timeout)
 
proc test() {.async.} = 
    let clientwrapper = ClientWrapper(http1HostnamePoolSize: 1, http1Multiplexer: initHttp1Multiplexer(), allowHTTP10: true, allowHTTP11: true, allowHTTP2: true)
    asyncCheck clientwrapper.sendRequest(parseUri("https://localhost:5000"), HttpGet, newHttpHeaders())
    asyncCheck clientwrapper.sendRequest(parseUri("https://localhost:5000"), HttpGet, newHttpHeaders())

when isMainModule:
    asyncCheck test()
    runForever()