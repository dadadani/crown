import std/os, std/strutils

{.used.}

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}

const VERSION_FILE_TEMPLATE = """#ifndef NGHTTP2VER_H
#define NGHTTP2VER_H

/**
 * @macro
 * Version number of the nghttp2 library release
 */
#define NGHTTP2_VERSION "%VERSIONSTRING%"

/**
 * @macro
 * Numerical representation of the version number of the nghttp2 library
 * release. This is a 24 bit number with 8 bits for major number, 8 bits
 * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
 */
#define NGHTTP2_VERSION_NUM %VERSIONNUM%

#endif /* NGHTTP2VER_H */
"""

const PATH = currentSourcePath() / ".." / "nghttp2"
const PATH_LIB = currentSourcePath() / ".." / "nghttp2/lib"


proc createVersionFile() =
    # dumb way of reading the version of nghttp2
    # I should really make something better, but I am too lazy right now

    let cmakeLists = readFile(PATH / "CMakeLists.txt")

    var splitVersion = cmakeLists.split("project(nghttp2 VERSION ")

    if splitVersion.len != 2:
        echo "createVersionFile: Invalid version split"
        return
    
    splitVersion = splitVersion[1].split(")")

    var version = splitVersion[0]
    
    splitVersion = version.split(".")
    if splitVersion.len != 3:
        echo "createVersionFile: Invalid parsed version"
        return

    let versionNumber = toHex(int32((parseInt(splitVersion[0]) shl 16) + (parseInt(splitVersion[1]) shl 8) + int32(parseInt(splitVersion[2]))))[2..<8]
    writeFile(PATH_LIB / "includes/nghttp2/nghttp2ver.h", VERSION_FILE_TEMPLATE.multiReplace(("%VERSIONSTRING%", version), ("%VERSIONNUM%", "0x" & versionNumber)))

static:
    createVersionFile()


{.passc: "-I" & PATH_LIB / "includes".}


{.compile: PATH_LIB / "nghttp2_buf.c".}
{.compile: PATH_LIB / "nghttp2_callbacks.c".}
{.compile: PATH_LIB / "nghttp2_debug.c".}
{.compile: PATH_LIB / "nghttp2_extpri.c".}
{.compile: PATH_LIB / "nghttp2_frame.c".}
{.compile: PATH_LIB / "nghttp2_hd.c".}
{.compile: PATH_LIB / "nghttp2_hd_huffman.c".}
{.compile: PATH_LIB / "nghttp2_hd_huffman_data.c".}
{.compile: PATH_LIB / "nghttp2_helper.c".}
{.compile: PATH_LIB / "nghttp2_http.c".}
{.compile: PATH_LIB / "nghttp2_map.c".}
{.compile: PATH_LIB / "nghttp2_mem.c".}
{.compile: PATH_LIB / "nghttp2_npn.c".}
{.compile: PATH_LIB / "nghttp2_option.c".}
{.compile: PATH_LIB / "nghttp2_outbound_item.c".}
{.compile: PATH_LIB / "nghttp2_pq.c".}
{.compile: PATH_LIB / "nghttp2_priority_spec.c".}
{.compile: PATH_LIB / "nghttp2_queue.c".}
{.compile: PATH_LIB / "nghttp2_rcbuf.c".}
{.compile: PATH_LIB / "nghttp2_session.c".}
{.compile: PATH_LIB / "nghttp2_stream.c".}
{.compile: PATH_LIB / "nghttp2_submit.c".}
{.compile: PATH_LIB / "nghttp2_version.c".}
{.compile: PATH_LIB / "sfparse.c".}
