{.emit: """#include <stdio.h>
#include <unistd.h>

typedef struct {
    void (*callback)();
} Scallback;


int csleep(Scallback callback) {
    usleep(5000000);
    callback.callback();

    usleep(5000000);
    printf("Done sleeping\n");
    return 0;
}"""}


proc callback() {.cdecl.} =
    echo "Callback called"
    raise newException(Exception, "Callback called")

type FCallback = proc (): void {.cdecl.}

type Scallback* {.importc: "Scallback".} = object
    callback*: FCallback

proc csleep(callback: Scallback): cint {.importc.}

when isMainModule:
    var cb = Scallback(callback: callback)
    discard csleep(cb)
    discard csleep(cb)
