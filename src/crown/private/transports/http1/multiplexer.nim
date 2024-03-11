# Multiplexer for http/1.1
# This module allows to multiplex several http/1.1 requests over a single instance.
import client
import pkg/uva, pkg/uva/handles, ../base_tcp, client
import std/tables, pkg/uva/resolveaddr
import std/times, base, std/strutils

type AddrHolder* = object
    hostname*: ptr AddrInfo

proc `=destroy`(x: AddrHolder) =
    uv_freeaddrinfo(x.hostname)


type Http1Multiplexer* = object 
    lastDestroy: int64
    pool: TableRef[string, (int64, Dasfdsfsdfds, seq[HTTP1Client], AddrHolder)]

proc initHttp1Multiplexer*(): Http1Multiplexer =
    result.pool = newTable[string, (int64, Dasfdsfsdfds, seq[HTTP1Client], AddrHolder)]()
    result.lastDestroy = now().toTime().toUnix()

proc destroyInactive*(m: var Http1Multiplexer, maxIdleTime = 300) {.async.} =
    ## Destroy inactive connections
    
    let now = now().toTime().toUnix()
    if now - m.lastDestroy < maxIdleTime:
        return

    m.lastDestroy = now

    var expired = newSeq[string]()
    for hostname, connections in m.pool:
        if now - connections[0] > maxIdleTime:
            for c in connections[2]:
                await c.socket.close()
            expired.add(hostname)
    for hostname in expired:
        m.pool.del(hostname)

proc exists*(m: var Http1Multiplexer, hostname: string): bool =
    return hostname in m.pool

proc add*(m: Http1Multiplexer, hostname: string, hostnameptr: ptr AddrInfo, firstClient: HTTP1Client, maxClients: int) =
    echo "Adding ", hostname
    m.pool[hostname] = (now().toTime().toUnix(), Dasfdsfsdfds(future: newFuture[void]()), newSeq[HTTP1Client](), AddrHolder(hostname: hostnameptr))
    m.pool[hostname][2].add(firstClient)
    echo "Adding ", maxClients
    for _ in 0..<maxClients:
        m.pool[hostname][2].add(HTTP1Client(socket: HttpTcpStream()))
    echo "done"
proc get*(m: Http1Multiplexer, hostname: string): Future[(ptr AddrInfo, HTTP1Client)] {.async.} =
    #asyncCheck destroyInactive(m)
    for conn in m.pool[hostname][2]:
        if conn.socket.isClosed or not conn.busy:
            conn.busy = true
            return (m.pool[hostname][3].hostname, conn)


    
    await m.pool[hostname][1].future
    m.pool[hostname][1].future = newFuture[void]()
    return await get(m, hostname)
    
import std/openssl, std/net, std/uri, std/httpclient
#[
proc send(mult: Http1Multiplexer, hostname: string) {.async.} =
    let conn = await mult.get(hostname)
    echo "Got connection: "
    echo "Got connection: ", conn.socket.isClosed
    echo await conn.sendRequest(parseUri("https://localhost:5000/"), HttpGet, newHttpHeaders())


proc test() {.async.} =
    var mult = Http1Multiplexer(pool: newTable[string, (int64, Dasfdsfsdfds, seq[HTTP1Client], AddrHolder)](), lastDestroy: now().toTime().toUnix())
    
    # create first connection
    let hostname = "localhost"
    let hostnameptr = await resolveAddrPtr(hostname, service = "5000")
    let connection = HTTP1Client(socket: HttpTcpStream(), allowHTTP11: true,)
    wrapSSL(connection.socket, newContext(verifyMode = CVerifyNone))
    echo "Connecting to ", hostname
    await connection.socket.connect(hostname, 5000.Port)
    echo "Connected to ", hostname
    mult.add(hostname, hostnameptr, connection, 0)
    connection.readComplete = mult.pool[hostname][1]
    echo "Added ", hostname
    # try to get connection
    asyncCheck send(mult, hostname)

    asyncCheck send(mult, hostname)
    asyncCheck send(mult, hostname)
    asyncCheck send(mult, hostname)
    asyncCheck send(mult, hostname)
    asyncCheck send(mult, hostname)


when isMainModule:
    asyncCheck test()
    runForever()

#[proc get*(m: var Http1Multiplexer, hostname: string): Future[HTTP1Client] {.async.} =
    asyncCheck destroyInactive(m)

    if hostname notin m.pool:
        m.pool[hostname] = (now().toTime().toUnix(), newFuture[void](), newSeq[HTTP1Client]())
        for i in 0 ..< m.maxClientsPerHostname:
            m.pool[hostname][2].add(HTTP1Client())#]
        
]#
proc initMultiplexer*(m: var Http1Multiplexer, maxClientsPerHostname: int) = 

    m.pool = newTable[string, (int64, Future[void], seq[HTTP1Client])]()
    m.maxClientsPerHostname = maxClientsPerHostname

]#