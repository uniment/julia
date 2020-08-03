module BinaryPlatforms

export AbstractPlatform, Platform, platform_dlext, tags, arch, os, libc, compiler_abi,
       libgfortran_version, libstdcxx_version, cxxstring_abi, parse_dl_name_version,
       detect_libgfortran_version, detect_libstdcxx_version, detect_cxxstring_abi,
       call_abi, wordsize, triplet, select_platform, platforms_match, platform_name
import .Libc.Libdl

abstract type AbstractPlatform; end
"""
    Platform

A `Platform` represents all relevant pieces of information that a julia process may need
to know about its execution environment, such as the processor architecture, operating
system, libc implementation, etc...  It is, at its heart, a key-value mapping of tags
(such as `arch`, `os`, `libc`, etc...) to values (such as `"arch" => "x86_64"`, or
`"os" => "windows"`, etc...).  `Platform` objects are extensible in that the tag mapping
is open for users to add their own mappings to, as long as the mappings do not conflict
with the set of reserved tags, which are as follows: `arch`, `os`, `libc`, `call_abi`,
`libgfortran_version`, `libstdcxx_version`, `cxxstring_abi` and `julia_version`.

Valid tags and values are composed of alphanumeric and period characters.  All tags and
values will be lowercased when stored to reduce variation.

Example:

    Platform("x86_64", "windows"; cuda = "10.1")
"""
struct Platform <: AbstractPlatform
    tags::Dict{String,String}

    function Platform(arch::String, os::String;
                      validate_strict::Bool = false,
                      kwargs...)
        # A wee bit of normalization
        os = lowercase(os)
        arch = lowercase(arch)
        if arch ∈ ("amd64",)
            arch = "x86_64"
        elseif arch ∈ ("i386", "i586")
            arch = "i686"
        elseif arch ∈ ("arm",)
            arch = "armv7l"
        elseif arch ∈ ("ppc64le",)
            arch = "powerpc64le"
        end

        tags = Dict{String,String}(
            "arch" => arch,
            "os" => os,
        )
        for (tag, value) in kwargs
            tag = lowercase(string(tag))
            if tag ∈ ("arch", "os")
                throw(ArgumentError("Cannot double-pass key $(tag)"))
            end

            # Drop `nothing` values; this means feature is not present or use default value.
            if value === nothing
                continue
            end

            # Normalize things that are known to be version numbers so that comparisons are easy.
            # Note that in our effort to be extremely compatible, we actually allow something that
            # doesn't parse nicely into a VersionNumber to persist, but if `validate_strict` is
            # set to `true`, it will cause an error later on.
            if tag ∈ ("libgfortran_version", "libstdcxx_version")
                normver(x::VersionNumber) = string(x)
                function normver(str::AbstractString)
                    v = tryparse(VersionNumber, str)
                    if v === nothing
                        # If this couldn't be parsed as a VersionNumber, return the original.
                        return str
                    end
                    # Otherwise, return the `string(VersionNumber(str))` version.
                    return normver(v)
                end
                value = normver(value)
            end

            # I know we said only alphanumeric and dots, but let's be generous so that we can expand
            # our support in the future while remaining as backwards-compatible as possible.  The
            # only characters that are absolutely disallowed right now are `-`, `+`, ` ` and things
            # that are illegal in filenames:
            nonos = raw"""+- /<>:"'\|?*"""
            if any(occursin(nono, tag) for nono in nonos)
                throw(ArgumentError("Invalid character in tag name \"$(tag)\"!"))
            end

            # Normalize and reject nonos
            value = lowercase(string(value))
            if any(occursin(nono, value) for nono in nonos)
                throw(ArgumentError("Invalid character in tag value \"$(value)\"!"))
            end
            tags[tag] = value
        end

        # Auto-map call_abi and libc where necessary:
        if os == "linux" && !haskey(tags, "libc")
            # Default to `glibc` on Linux
            tags["libc"] = "glibc"
        end
        if os == "linux" && arch ∈ ("armv7l", "armv6l") && "call_abi" ∉ keys(tags)
            # default `call_abi` to `eabihf` on 32-bit ARM
            tags["call_abi"] = "eabihf"
        end

        # If the user is asking for strict validation, do so.
        if validate_strict
            validate_tags(tags)
        end

        return new(tags)
    end
end

# Other `Platform` types can override this (I'm looking at you, `AnyPlatform`)
tags(p::Platform) = p.tags

# Allow us to easily serialize Platform objects
function Base.repr(p::Platform; context=nothing)
    str = string(
        "Platform(",
        repr(arch(p)),
        ", ",
        repr(os(p)),
        "; ",
        join(("$(k) = $(repr(v))" for (k, v) in tags(p) if k ∉ ("arch", "os")), ", "),
        ")",
    )
end

# Simple equality definition; for compatibility testing, use `platforms_match()`
Base.:(==)(a::AbstractPlatform, b::AbstractPlatform) = tags(a) == tags(b)

function validate_tags(tags::Dict)
    throw_invalid_key(k) = throw(ArgumentError("Key \"$(k)\" cannot have value \"$(tags[k])\""))
    ARCHITECTURE_FLAGS = Dict(
        "x86_64" => ["x86_64", "avx", "avx2", "avx512"],
        "i686" => ["prescott"],
        "armv7l" => ["armv7l", "neon", "vfp4"],
        "armv6l" => ["generic"],
        "aarch64" => ["armv8", "thunderx2", "carmel"],
        "powerpc64le" => ["generic"],
    )
    # Validate `arch`
    if tags["arch"] ∉ keys(ARCHITECTURE_FLAGS)
        throw_invalid_key("arch")
    end
    # Validate `os`
    if tags["os"] ∉ ("linux", "macos", "freebsd", "windows")
        throw_invalid_key("os")
    end
    # Validate `os`/`arch` combination
    throw_os_mismatch() = throw(ArgumentError("Invalid os/arch combination: $(tags["os"])/$(tags["arch"])"))
    if tags["os"] == "windows" && tags["arch"] ∉ ("x86_64", "i686", "armv7l", "aarch64")
        throw_os_mismatch()
    end
    if tags["os"] == "macos" && tags["arch"] ∉ ("x86_64", "aarch64")
        throw_os_mismatch()
    end

    # Validate `os`/`libc` combination
    throw_libc_mismatch() = throw(ArgumentError("Invalid os/libc combination: $(tags["os"])/$(tags["libc"])"))
    if tags["os"] == "linux"
        # Linux always has a `libc` entry
        if tags["libc"] ∉ ("glibc", "musl")
            throw_libc_mismatch()
        end
    else
        # Nothing else is allowed to have a `libc` entry
        if haskey(tags, "libc")
            throw_libc_mismatch()
        end
    end

    # Validate `os`/`arch`/`call_abi` combination
    throw_call_abi_mismatch() = throw(ArgumentError("Invalid os/arch/call_abi combination: $(tags["os"])/$(tags["arch"])/$(tags["call_abi"])"))
    if tags["os"] == "linux" && tags["arch"] ∈ ("armv7l", "armv6l")
        # If an ARM linux has does not have `call_abi` set to something valid, be sad.
        if !haskey(tags, "call_abi") || tags["call_abi"] ∉ ("eabihf", "eabi")
            throw_call_abi_mismatch()
        end
    else
        # Nothing else should have a `call_abi`.
        if haskey(tags, "call_abi")
            throw_call_abi_mismatch()
        end
    end

    # Validate `libgfortran_version` is a parsable `VersionNumber`
    throw_version_number(k) = throw(ArgumentError("\"$(k)\" cannot have value \"$(tags[k])\", must be a valid VersionNumber"))
    if "libgfortran_version" in keys(tags) && tryparse(VersionNumber, tags["libgfortran_version"]) === nothing
        throw_version_number("libgfortran_version")
    end

    # Validate `libstdcxx_version` is a parsable `VersionNumber`
    if "libstdcxx_version" in keys(tags) && tryparse(VersionNumber, tags["libstdcxx_version"]) === nothing
        throw_version_number("libstdcxx_version")
    end

    # Validate `cxxstring_abi` is one of the two valid options:
    if "cxxstring_abi" in keys(tags) && tags["cxxstring_abi"] ∉ ("cxx03", "cxx11")
        throw_invalid_key("cxxstring_abi")
    end

    # Validate `march` is one of our recognized microarchitectures for the architecture we're advertising
    if "march" in keys(tags) && tags["march"] ∉ ARCHITECTURE_FLAGS[tags["arch"]]
        throw(ArgumentError("\"march\" cannot have value \"$(tags["march"])\" for arch $(tags["arch"])"))
    end

    # Validate `cuda` is a parsable `VersionNumber`
    if "cuda" in keys(tags) && tryparse(VersionNumber, tags["cuda"]) === nothing
        throw_version_number("cuda")
    end
end


"""
    arch(p::AbstractPlatform)

Get the architecture for the given `Platform` object as a `String`.

# Examples
```jldoctest
julia> arch(Platform("aarch64", "Linux"))
"aarch64"

julia> arch(Platform("amd64", "freebsd"))
"x86_64"
```
"""
arch(p::AbstractPlatform) = get(tags(p), "arch", nothing)

"""
    os(p::AbstractPlatform)

Get the operating system for the given `Platform` object as a `String`.

# Examples
```jldoctest
julia> os(Platform("armv7l", "Linux"))
"linux"

julia> os(Platform("aarch64", "macos"))
"macos"
```
"""
os(p::AbstractPlatform) = get(tags(p), "os", nothing)

# As a special helper, it's sometimes useful to know the current OS at compile-time
function os()
    if Sys.iswindows()
        return "windows"
    elseif Sys.isapple()
        return "macos"
    elseif Sys.isbsd()
        return "freebsd"
    else
        return "linux"
    end
end

"""
    libc(p::AbstractPlatform)

Get the libc for the given `Platform` object as a `String`.  Returns `nothing` on
platforms with no explicit `libc` choices (which is most platforms).

# Examples
```jldoctest
julia> libc(Platform("armv7l", "Linux"))
"glibc"

julia> libc(Platform("aarch64", "linux"; libc="musl"))
"musl"

julia> libc(Platform("i686", "Windows"))
```
"""
libc(p::AbstractPlatform) = get(tags(p), "libc", nothing)

"""
    call_abi(p::AbstractPlatform)

Get the call ABI for the given `Platform` object as a `String`.  Returns `nothing` on
platforms with no explicit `call_abi` choices (which is most platforms).

# Examples
```jldoctest
julia> call_abi(Platform("armv7l", "Linux"))
"eabihf"

julia> call_Abi(Platform("x86_64", "macos"))
```
"""
call_abi(p::AbstractPlatform) = get(tags(p), "call_abi", nothing)

"""
    platform_name(p::AbstractPlatform)

Get the "platform name" of the given platform, returning e.g. "Linux" or "Windows".
"""
function platform_name(p::AbstractPlatform)
    names = Dict(
        "linux" => "Linux",
        "macos" => "macOS",
        "windows" => "Windows",
        "freebsd" => "FreeBSD",
        nothing => "Unknown",
    )
    return names[os(p)]
end

function VNorNothing(d::Dict, key)
    v = get(d, key, nothing)
    if v === nothing
        return nothing
    end
    return VersionNumber(v)
end

"""
    libgfortran_version(p::AbstractPlatform)

Get the libgfortran version dictated by this `Platform` object as a `VersionNumber`,
or `nothing` if no compatibility bound is imposed.
"""
libgfortran_version(p::AbstractPlatform) = VNorNothing(tags(p), "libgfortran_version")

"""
libstdcxx_version(p::AbstractPlatform)

Get the libstdc++ version dictated by this `Platform` object, or `nothing` if no
compatibility bound is imposed.
"""
libstdcxx_version(p::AbstractPlatform) = VNorNothing(tags(p), "libstdcxx_version")

"""
cxxstring_abi(p::AbstractPlatform)

Get the c++ string ABI dictated by this `Platform` object, or `nothing` if no ABI is imposed.
"""
cxxstring_abi(p::AbstractPlatform) = get(tags(p), "cxxstring_abi", nothing)

"""
    wordsize(p::AbstractPlatform)

Get the word size for the given `Platform` object.

# Examples
```jldoctest
julia> wordsize(Platform("armv7l", "linux"))
32

julia> wordsize(Platform("x86_64", "macos"))
64
```
"""
wordsize(p::AbstractPlatform) = (arch(p) ∈ ("i686", "armv6l", "armv7l")) ? 32 : 64

"""
    triplet(p::AbstractPlatform; exclude_tags::Vector{String})

Get the target triplet for the given `Platform` object as a `String`.

# Examples
```jldoctest
julia> triplet(Platform("x86_64", "MacOS"))
"x86_64-apple-darwin14"

julia> triplet(Platform("i686", "Windows"))
"i686-w64-mingw32"

julia> triplet(Platform("armv7l", "Linux"; libgfortran_version="3")
"armv7l-linux-gnueabihf-libgfortran3"
```
"""
function triplet(p::AbstractPlatform)
    str = string(
        arch(p),
        os_str(p),
        libc_str(p),
        call_abi_str(p),
    )

    # Tack on optional compiler ABI flags
    if libgfortran_version(p) !== nothing
        str = string(str, "-libgfortran", libgfortran_version(p).major)
    end
    if libstdcxx_version(p) !== nothing
        str = string(str, "-libstdcxx", libstdcxx_version(p).patch)
    end
    if cxxstring_abi(p) !== nothing
        str = string(str, "-", cxxstring_abi(p))
    end

    # Tack on all extra tags
    for (tag, val) in tags(p)
        if tag ∈ ("os", "arch", "libc", "call_abi", "libgfortran_version", "libstdcxx_version", "cxxstring_abi")
            continue
        end
        str = string(str, "-", tag, "+", val)
    end
    return str
end

function os_str(p::AbstractPlatform)
    if os(p) == "linux"
        return "-linux"
    elseif os(p) == "macos"
        if arch(p) == "aarch64"
            return "-apple-darwin20"
        else
            return "-apple-darwin14"
        end
    elseif os(p) == "windows"
        return "-w64-mingw32"
    elseif os(p) == "freebsd"
        return "-unknown-freebsd11.1"
    else
        return "-unknown"
    end
end

# Helper functions for Linux and FreeBSD libc/abi mishmashes
function libc_str(p::AbstractPlatform)
    if libc(p) === nothing
        return ""
    elseif libc(p) === "glibc"
        return "-gnu"
    else
        return string("-", libc(p))
    end
end
call_abi_str(p::AbstractPlatform) = (call_abi(p) === nothing) ? "" : call_abi(p)

Sys.isapple(p::AbstractPlatform) = os(p) == "macos"
Sys.islinux(p::AbstractPlatform) = os(p) == "linux"
Sys.iswindows(p::AbstractPlatform) = os(p) == "windows"
Sys.isfreebsd(p::AbstractPlatform) = os(p) == "freebsd"
Sys.isbsd(p::AbstractPlatform) = os(p) ∈ ("freebsd", "macos")

"""
    parse(::Type{Platform}, triplet::AbstractString)

Parses a string platform triplet back into a `Platform` object.
"""
function Base.parse(::Type{Platform}, triplet::AbstractString; validate_strict::Bool = false)
    # We're going to build a mondo regex here to parse everything:
    arch_mapping = Dict(
        "x86_64" => "(x86_|amd)64",
        "i686" => "i\\d86",
        "aarch64" => "(aarch64|arm64)",
        "armv7l" => "arm(v7l)?", # if we just see `arm-linux-gnueabihf`, we assume it's `armv7l`
        "armv6l" => "armv6l",
        "powerpc64le" => "p(ower)?pc64le",
    )
    os_mapping = Dict(
        "macos" => "-apple-darwin[\\d\\.]*",
        "freebsd" => "-(.*-)?freebsd[\\d\\.]*",
        "windows" => "-w64-mingw32",
        "linux" => "-(.*-)?linux",
    )
    libc_mapping = Dict(
        "libc_nothing" => "",
        "glibc" => "-gnu",
        "musl" => "-musl",
    )
    call_abi_mapping = Dict(
        "call_abi_nothing" => "",
        "eabihf" => "eabihf",
        "eabi" => "eabi",
    )
    libgfortran_version_mapping = Dict(
        "libgfortran_nothing" => "",
        "libgfortran3" => "(-libgfortran3)|(-gcc4)", # support old-style `gccX` versioning
        "libgfortran4" => "(-libgfortran4)|(-gcc7)",
        "libgfortran5" => "(-libgfortran5)|(-gcc8)",
    )
    libstdcxx_version_mapping = Dict(
        "libstdcxx_nothing" => "",
        # This is sadly easier than parsing out the digit directly
        ("libstdcxx$(idx)" => "-libstdcxx$(idx)" for idx in 18:26)...,
    )
    cxxstring_abi_mapping = Dict(
        "cxxstring_nothing" => "",
        "cxx03" => "-cxx03",
        "cxx11" => "-cxx11",
    )

    # Helper function to collapse dictionary of mappings down into a regex of
    # named capture groups joined by "|" operators
    c(mapping) = string("(",join(["(?<$k>$v)" for (k, v) in mapping], "|"), ")")

    triplet_regex = Regex(string(
        "^",
        # First, the core triplet; arch/os/libc/call_abi
        c(arch_mapping),
        c(os_mapping),
        c(libc_mapping),
        c(call_abi_mapping),
        # Next, optional things, like libgfortran/libstdcxx/cxxstring abi
        c(libgfortran_version_mapping),
        c(libstdcxx_version_mapping),
        c(cxxstring_abi_mapping),
        # Finally, the catch-all for extended tags
        "(?<tags>(?:-[^-]+\\+[^-]+)*)?",
        "\$",
    ))

    m = match(triplet_regex, triplet)
    if m !== nothing
        # Helper function to find the single named field within the giant regex
        # that is not `nothing` for each mapping we give it.
        get_field(m, mapping) = begin
            for k in keys(mapping)
                if m[k] !== nothing
                    # Convert our sentinel `nothing` values to actual `nothing`
                    if endswith(k, "_nothing")
                        return nothing
                    end
                    # Convert libgfortran/libstdcxx version numbers
                    if startswith(k, "libgfortran")
                        return VersionNumber(parse(Int,k[12:end]))
                    elseif startswith(k, "libstdcxx")
                        return VersionNumber(3, 4, parse(Int,k[10:end]))
                    else
                        return k
                    end
                end
            end
        end

        # Extract the information we're interested in:
        arch = get_field(m, arch_mapping)
        os = get_field(m, os_mapping)
        libc = get_field(m, libc_mapping)
        call_abi = get_field(m, call_abi_mapping)
        libgfortran_version = get_field(m, libgfortran_version_mapping)
        libstdcxx_version = get_field(m, libstdcxx_version_mapping)
        cxxstring_abi = get_field(m, cxxstring_abi_mapping)
        function split_tags(tagstr)
            tag_fields = filter(!isempty, split(tagstr, "-"))
            if isempty(tag_fields)
                return Pair{String,String}[]
            end
            return map(v -> Symbol(v[1]) => v[2], split.(tag_fields, "+"))
        end
        tags = split_tags(m["tags"])

        return Platform(
            arch, os;
            validate_strict,
            libc,
            call_abi,
            libgfortran_version,
            libstdcxx_version,
            cxxstring_abi,
            tags...,
        )
    end
    throw(ArgumentError("Platform `$(triplet)` is not an officially supported platform"))
end

function Base.tryparse(::Type{Platform}, triplet::AbstractString)
    try
        parse(Platform, triplet)
    catch e
        if isa(e, InterruptException)
            rethrow(e)
        end
        return nothing
    end
end

"""
    platform_dlext(p::AbstractPlatform = Platform())

Return the dynamic library extension for the given platform, defaulting to the
currently running platform.  E.g. returns "so" for a Linux-based platform,
"dll" for a Windows-based platform, etc...
"""
function platform_dlext(p::AbstractPlatform = Platform())
    if os(p) == "windows"
        return "dll"
    elseif os(p) == "macos"
        return "dylib"
    else
        return "so"
    end
end

"""
    parse_dl_name_version(path::AbstractString, platform::AbstractPlatform)

Given a path to a dynamic library, parse out what information we can
from the filename.  E.g. given something like "lib/libfoo.so.3.2",
this function returns `"libfoo", v"3.2"`.  If the path name is not a
valid dynamic library, this method throws an error.  If no soversion
can be extracted from the filename, as in "libbar.so" this method
returns `"libbar", nothing`.
"""
function parse_dl_name_version(path::AbstractString, os::String)
    # Use an extraction regex that matches the given OS
    local dlregex
    if os == "windows"
        # On Windows, libraries look like `libnettle-6.dll`
        dlregex = r"^(.*?)(?:-((?:[\.\d]+)*))?\.dll$"
    elseif os == "macos"
        # On OSX, libraries look like `libnettle.6.3.dylib`
        dlregex = r"^(.*?)((?:\.[\d]+)*)\.dylib$"
    else
        # On Linux and FreeBSD, libraries look like `libnettle.so.6.3.0`
        dlregex = r"^(.*?).so((?:\.[\d]+)*)$"
    end

    m = match(dlregex, basename(path))
    if m === nothing
        throw(ArgumentError("Invalid dynamic library path '$path'"))
    end

    # Extract name and version
    name = m.captures[1]
    version = m.captures[2]
    if version === nothing || isempty(version)
        version = nothing
    else
        version = VersionNumber(strip(version, '.'))
    end
    return name, version
end

"""
    detect_libgfortran_version()

Inspects the current Julia process to determine the libgfortran version this Julia is
linked against (if any).
"""
function detect_libgfortran_version()
    libgfortran_paths = filter(x -> occursin("libgfortran", x), Libdl.dllist())
    if isempty(libgfortran_paths)
        # One day, I hope to not be linking against libgfortran in base Julia
        return nothing
    end
    libgfortran_path = first(libgfortran_paths)

    name, version = parse_dl_name_version(libgfortran_path, os())
    if version === nothing
        # Even though we complain about this, we allow it to continue in the hopes that
        # we shall march on to a BRIGHTER TOMORROW.  One in which we are not shackled
        # by the constraints of libgfortran compiler ABIs upon our precious programming
        # languages; one where the mistakes of yesterday are mere memories and not
        # continual maintenance burdens upon the children of the dawn; one where numeric
        # code may be cleanly implemented in a modern language and not bestowed onto the
        # next generation by grizzled ancients, documented only with a faded yellow
        # sticky note that bears a hastily-scribbled "good luck".
        @warn("Unable to determine libgfortran version from '$(libgfortran_path)'")
    end
    return version
end

"""
    detect_libstdcxx_version()

Inspects the currently running Julia process to find out what version of libstdc++
it is linked against (if any).
"""
function detect_libstdcxx_version()
    libstdcxx_paths = filter(x -> occursin("libstdc++", x), Libdl.dllist())
    if isempty(libstdcxx_paths)
        # This can happen if we were built by clang, so we don't link against
        # libstdc++ at all.
        return nothing
    end

    # Brute-force our way through GLIBCXX_* symbols to discover which version we're linked against
    hdl = Libdl.dlopen(first(libstdcxx_paths))
    for minor_version in 26:-1:18
        if Libdl.dlsym(hdl, "GLIBCXX_3.4.$(minor_version)"; throw_error=false) !== nothing
            Libdl.dlclose(hdl)
            return VersionNumber("3.4.$(minor_version)")
        end
    end
    Libdl.dlclose(hdl)
    return nothing
end

"""
    detect_cxxstring_abi()

Inspects the currently running Julia process to see what version of the C++11 string ABI
it was compiled with (this is only relevant if compiled with `g++`; `clang` has no
incompatibilities yet, bless its heart).  In reality, this actually checks for symbols
within LLVM, but that is close enough for our purposes, as you can't mix configurations
between Julia and LLVM; they must match.
"""
function detect_cxxstring_abi()
    # First, if we're not linked against libstdc++, then early-exit because this doesn't matter.
    libstdcxx_paths = filter(x -> occursin("libstdc++", x), Libdl.dllist())
    if isempty(libstdcxx_paths)
        # We were probably built by `clang`; we don't link against `libstdc++`` at all.
        return nothing
    end

    function open_libllvm(f::Function)
        for lib_name in ("libLLVM", "LLVM", "libLLVMSupport")
            hdl = Libdl.dlopen_e(lib_name)
            if hdl != C_NULL
                try
                    return f(hdl)
                finally
                    Libdl.dlclose(hdl)
                end
            end
        end
        error("Unable to open libLLVM!")
    end

    return open_libllvm() do hdl
        # Check for llvm::sys::getProcessTriple(), first without cxx11 tag:
        if Libdl.dlsym_e(hdl, "_ZN4llvm3sys16getProcessTripleEv") != C_NULL
            return "cxx03"
        elseif Libdl.dlsym_e(hdl, "_ZN4llvm3sys16getProcessTripleB5cxx11Ev") != C_NULL
            return "cxx11"
        else
            @warn("Unable to find llvm::sys::getProcessTriple() in libLLVM!")
            return nothing
        end
    end
end

"""
    host_triplet()

Build host triplet out of `Sys.MACHINE` and various introspective utilities that
detect compiler ABI values such as `libgfortran_version`, `libstdcxx_version` and
`cxxstring_abi`.  We do this without using any `Platform` tech as it must run before
we have much of that built.
"""
function host_triplet()
    str = Sys.MACHINE
    libgfortran_version = detect_libgfortran_version()
    if libgfortran_version !== nothing
        str = string(str, "-libgfortran", libgfortran_version.major)
    end

    libstdcxx_version = detect_libstdcxx_version()
    if libstdcxx_version !== nothing
        str = string(str, "-libstdcxx", libstdcxx_version.patch)
    end

    cxxstring_abi = detect_cxxstring_abi()
    if cxxstring_abi !== nothing
        str = string(str, "-", cxxstring_abi)
    end

    # Add on julia_version extended tag
    str = string(str, "-julia_version+", VersionNumber(VERSION.major, VERSION.minor, VERSION.patch))
    return str
end

# Cache the host platform value, and return it if someone asks for just `Platform()`.
default_platkey = parse(Platform, host_triplet())
"""
    Platform()

Return the `Platform` object that corresponds to the current host process.
"""
function Platform()
    global default_platkey
    return default_platkey
end

"""
    platforms_match(a::AbstractPlatform, b::AbstractPlatform)

Return `true` if `a` and `b` are matching platforms, where matching is determined by
comparing all keys contained within the platform objects, and if both objects contain
entries for that key, they must match.
"""
function platforms_match(a::AbstractPlatform, b::AbstractPlatform)
    for k in union(keys(tags(a)), keys(tags(b)))
        ak = get(tags(a), k, nothing)
        bk = get(tags(b), k, nothing)
        if !(ak === nothing || bk === nothing || ak == bk)
            return false
        end
    end
    return true
end

function platforms_match(a::AbstractString, b::AbstractPlatform)
    return platforms_match(parse(Platform, a), b)
end
function platforms_match(a::AbstractPlatform, b::AbstractString)
    return platforms_match(a, parse(Platform, b))
end
platforms_match(a::AbstractString, b::AbstractString) = platforms_match(parse(Platform, a), parse(Platform, b))

"""
    select_platform(download_info::Dict, platform::AbstractPlatform = Platform())

Given a `download_info` dictionary mapping platforms to some value, choose
the value whose key best matches `platform`, returning `nothing` if no matches
can be found.

Platform attributes such as architecture, libc, calling ABI, etc... must all
match exactly, however attributes such as compiler ABI can have wildcards
within them such as `nothing` which matches any version of GCC.
"""
function select_platform(download_info::Dict, platform::AbstractPlatform = Platform())
    ps = collect(filter(p -> platforms_match(p, platform), keys(download_info)))

    if isempty(ps)
        return nothing
    end

    # At this point, we may have multiple possibilities.  E.g. if, in the future,
    # Julia can be built without a direct dependency on libgfortran, we may match
    # multiple tarballs that vary only within their libgfortran ABI.  To narrow it
    # down, we just sort by triplet, then pick the last one.  This has the effect
    # of generally choosing the latest release (e.g. a `libgfortran5` tarball
    # rather than a `libgfortran3` tarball)
    p = last(sort(ps, by = p -> triplet(p)))
    return download_info[p]
end

end # module
