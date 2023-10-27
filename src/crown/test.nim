import private/transports/http1/connection
import asyncdispatch
import asyncnet, uri
import httpcore, options, asyncstreams, net
import asyncfile


proc cb(callback: FutureStream[string]) = 
    echo waitFor callback.read

proc ac() {.async.} = 
    echo "dial"

    let net = asyncnet.newAsyncSocket(buffered = false)
    let ssl = newContext()
    wrapSocket(ssl, net)
    await net.connect("archmirror.it", 443.Port)
    echo "dial done"
    let http1 = HTTP1Client(allowHTTP11: true, socket: net)
    echo "send request"
    let headers = newHttpHeaders()
    var req = await http1.sendRequest(uri.parseUri("https://archmirror.it/repos/extra/os/x86_64/linux-hardened-6.5.7.hardened1-1-x86_64.pkg.tar.zst"), HttpGet, headers)
    echo req
    echo "send request done"
    if not req[2].isSome:
        echo "no response"
    else:
        discard
        #let file = openAsync("1gb.bin", fmReadWrite)

        #await file.writeFromStream(req[2].get)
        #echo "akk"


   # else:
        #while not req[2].get.finished:
            #echo "LINEBELLO", await req[2].get.read()
    
        


asyncCheck ac()
runForever()
