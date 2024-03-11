import ../base_tcp

type HTTP1Base* = ref object of RootObj
    allowHTTP10*: bool
    allowHTTP11*: bool
    allowUpgradeToHTTP2*: bool
    socket*: HttpTcpStream
    connectionKeepAlive*: bool
