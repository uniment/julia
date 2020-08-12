module Artifacts

import Base: get, SHA1
using Base.BinaryPlatforms, Base.TOML

# TODO:
#  * Split download_artifact implementation into separate module? (Maybe not, if libcurl is nicely integrated)
#  * Add utility functions to generate tree of primal hashes from tarball
#    * Also utility functions to merge trees of primal hashes together
#  * Add ability to extract pieces of artifact into directory
#    * Need to be careful to extract only files that don't already exist or be sure we can overwrite
#    * record stored primal hashes in TOML file in `~/.julia/artifacts/<treehash>/toml`
#    * If all primal hashes merge to the root hash, delete the TOML file.

export artifact_exists, artifact_path, remove_artifact, verify_artifact,
       artifact_meta, artifact_hash, find_artifacts_toml, @artifact_str

"""
    parse_toml(path::AbstractString)

Uses Base.TOML to parse a TOML file
"""
function parse_toml(path::AbstractString)
    p = Base.TOML.Parser()
    Base.TOML.reinit!(p, read(path, String); filepath=path)
    return Base.TOML.parse(p)
end

# keep in sync with Base.project_names and Base.manifest_names
const artifact_names = ("JuliaArtifacts.toml", "Artifacts.toml")

const ARTIFACTS_DIR_OVERRIDE = Ref{Union{String,Nothing}}(nothing)
"""
    with_artifacts_directory(f::Function, artifacts_dir::String)

Helper function to allow temporarily changing the artifact installation and search
directory.  When this is set, no other directory will be searched for artifacts, and new
artifacts will be installed within this directory.  Similarly, removing an artifact will
only effect the given artifact directory.  To layer artifact installation locations, use
the typical Julia depot path mechanism.
"""
function with_artifacts_directory(f::Function, artifacts_dir::String)
    try
        ARTIFACTS_DIR_OVERRIDE[] = artifacts_dir
        f()
    finally
        ARTIFACTS_DIR_OVERRIDE[] = nothing
    end
end

"""
    artifacts_dirs(args...)

Return a list of paths joined into all possible artifacts directories, as dictated by the
current set of depot paths and the current artifact directory override via the method
`with_artifacts_dir()`.
"""
function artifacts_dirs(args...)
    if ARTIFACTS_DIR_OVERRIDE[] === nothing
        return [abspath(depot, "artifacts", args...) for depot in Base.DEPOT_PATH]
    else
        # If we've been given an override, use _only_ that directory.
        return [abspath(ARTIFACTS_DIR_OVERRIDE[], args...)]
    end
end

"""
    ARTIFACT_OVERRIDES

Artifact locations can be overridden by writing `Override.toml` files within the artifact
directories of Pkg depots.  For example, in the default depot `~/.julia`, one may create
a `~/.julia/artifacts/Override.toml` file with the following contents:

    78f35e74ff113f02274ce60dab6e92b4546ef806 = "/path/to/replacement"
    c76f8cda85f83a06d17de6c57aabf9e294eb2537 = "fb886e813a4aed4147d5979fcdf27457d20aa35d"

    [d57dbccd-ca19-4d82-b9b8-9d660942965b]
    c_simple = "/path/to/c_simple_dir"
    libfoo = "fb886e813a4aed4147d5979fcdf27457d20aa35d""

This file defines four overrides; two which override specific artifacts identified
through their content hashes, two which override artifacts based on their bound names
within a particular package's UUID.  In both cases, there are two different targets of
the override: overriding to an on-disk location through an absolutet path, and
overriding to another artifact by its content-hash.
"""
const ARTIFACT_OVERRIDES = Ref{Union{Dict,Nothing}}(nothing)
function load_overrides(;force::Bool = false)
    if ARTIFACT_OVERRIDES[] !== nothing && !force
        return ARTIFACT_OVERRIDES[]
    end

    # We organize our artifact location overrides into two camps:
    #  - overrides per UUID with artifact names mapped to a new location
    #  - overrides per hash, mapped to a new location.
    #
    # Overrides per UUID/bound name are intercepted upon Artifacts.toml load, and new
    # entries within the "hash" overrides are generated on-the-fly.  Thus, all redirects
    # mechanisticly happen through the "hash" overrides.
    overrides = Dict(
        # Overrides by UUID
        :UUID => Dict{Base.UUID,Dict{String,Union{String,SHA1}}}(),

        # Overrides by hash
        :hash => Dict{SHA1,Union{String,SHA1}}(),
    )

    for override_file in reverse(artifacts_dirs("Overrides.toml"))
        !isfile(override_file) && continue

        # Load the toml file
        depot_override_dict = parse_toml(override_file)

        function parse_mapping(mapping::String, name::String)
            if !isabspath(mapping) && !isempty(mapping)
                try
                    mapping = Base.SHA1(mapping)
                catch e
                    @error("Invalid override in '$(override_file)': entry '$(name)' must map to an absolute path or SHA1 hash!")
                    rethrow()
                end
            end
            return mapping
        end
        function parse_mapping(mapping::Dict, name::String)
            return Dict(k => parse_mapping(v, name) for (k, v) in mapping)
        end

        for (k, mapping) in depot_override_dict
            # First, parse the mapping. Is it an absolute path, a valid SHA1-hash, or neither?
            try
                mapping = parse_mapping(mapping, k)
            catch
                @error("Invalid override in '$(override_file)': failed to parse entry `$(k)`")
                continue
            end

            # Next, determine if this is a hash override or a UUID/name override
            if isa(mapping, String) || isa(mapping, SHA1)
                # if this mapping is a direct mapping (e.g. a String), store it as a hash override
                hash = try
                    Base.SHA1(hex2bytes(k))
                catch
                    @error("Invalid override in '$(override_file)': Invalid SHA1 hash '$(k)'")
                    continue
                end

                # If this mapping is the empty string, un-override it
                if mapping == ""
                    delete!(overrides[:hash], hash)
                else
                    overrides[:hash][hash] = mapping
                end
            elseif isa(mapping, Dict)
                # Convert `k` into a uuid
                uuid = try
                    Base.UUID(k)
                catch
                    @error("Invalid override in '$(override_file)': Invalid UUID '$(k)'")
                    continue
                end

                # If this mapping is itself a dict, store it as a set of UUID/artifact name overrides
                if !haskey(overrides[:UUID], uuid)
                    overrides[:UUID][uuid] = Dict{String,Union{String,SHA1}}()
                end

                # For each name in the mapping, update appropriately
                for name in keys(mapping)
                    # If the mapping for this name is the empty string, un-override it
                    if mapping[name] == ""
                        delete!(overrides[:UUID][uuid], name)
                    else
                        # Otherwise, store it!
                        overrides[:UUID][uuid][name] = mapping[name]
                    end
                end
            end
        end
    end

    ARTIFACT_OVERRIDES[] = overrides
end

# Helpers to map an override to an actual path
map_override_path(x::String) = x
map_override_path(x::SHA1) = artifact_path(x)
map_override_path(x::Nothing) = nothing

"""
    query_override(hash::SHA1; overrides::Dict = load_overrides())

Query the loaded `<DEPOT>/artifacts/Overrides.toml` settings for artifacts that should be
redirected to a particular path or another content-hash.
"""
function query_override(hash::SHA1; overrides::Dict = load_overrides())
    return map_override_path(get(overrides[:hash], hash, nothing))
end
function query_override(pkg::Base.UUID, artifact_name::String; overrides::Dict = load_overrides())
    if haskey(overrides[:UUID], pkg)
        return map_override_path(get(overrides[:UUID][pkg], artifact_name, nothing))
    end
    return nothing
end

"""
    artifact_paths(hash::SHA1; honor_overrides::Bool=true)

Return all possible paths for an artifact given the current list of depots as returned
by `Pkg.depots()`.  All, some or none of these paths may exist on disk.
"""
function artifact_paths(hash::SHA1; honor_overrides::Bool=true)
    # First, check to see if we've got an override:
    if honor_overrides
        override = query_override(hash)
        if override !== nothing
            return [override]
        end
    end

    return artifacts_dirs(bytes2hex(hash.bytes))
end

"""
    artifact_path(hash::SHA1; honor_overrides::Bool=true)

Given an artifact (identified by SHA1 git tree hash), return its installation path.  If
the artifact does not exist, returns the location it would be installed to.

!!! compat "Julia 1.3"
    This function requires at least Julia 1.3.
"""
function artifact_path(hash::SHA1; honor_overrides::Bool=true)
    # Get all possible paths (rooted in all depots)
    possible_paths = artifact_paths(hash; honor_overrides=honor_overrides)

    # Find the first path that exists and return it
    for p in possible_paths
        if isdir(p)
            return p
        end
    end

    # If none exist, then just return the one that would exist within `depots1()`.
    return first(possible_paths)
end

"""
    artifact_exists(hash::SHA1; honor_overrides::Bool=true)

Returns whether or not the given artifact (identified by its sha1 git tree hash) exists
on-disk.  Note that it is possible that the given artifact exists in multiple locations
(e.g. within multiple depots).

!!! compat "Julia 1.3"
    This function requires at least Julia 1.3.
"""
function artifact_exists(hash::SHA1; honor_overrides::Bool=true)
    return any(isdir.(artifact_paths(hash; honor_overrides=honor_overrides)))
end

"""
    unpack_platform(entry::Dict, name::String, artifacts_toml::String)

Given an `entry` for the artifact named `name`, located within the file `artifacts_toml`,
returns the `Platform` object that this entry specifies.  Returns `nothing` on error.
"""
function unpack_platform(entry::Dict, name::String, artifacts_toml::String)
    if !haskey(entry, "os")
        @error("Invalid artifacts file at '$(artifacts_toml)': platform-specific artifact entry '$name' missing 'os' key")
        return nothing
    end

    if !haskey(entry, "arch")
        @error("Invalid artifacts file at '$(artifacts_toml)': platform-specific artifact entrty '$name' missing 'arch' key")
        return nothing
    end

    # Collect all String-valued mappings in `entry` and use them as tags
    tags = Dict(Symbol(k) => v for (k, v) in entry if isa(v, String))
    # Removing some known entries that shouldn't be passed through `tags`
    delete!(tags, :os)
    delete!(tags, :arch)
    delete!(tags, Symbol("git-tree-sha1"))
    return Platform(entry["arch"], entry["os"]; tags...)
end

function pack_platform!(meta::Dict, p::Platform)
    for (k, v) in tags(p)
        if v !== nothing
            meta[k] = v
        end
    end
    return meta
end

"""
    load_artifacts_toml(artifacts_toml::String;
                        pkg_uuid::Union{UUID,Nothing}=nothing)

Loads an `(Julia)Artifacts.toml` file from disk.  If `pkg_uuid` is set to the `UUID` of the
owning package, UUID/name overrides stored in a depot `Overrides.toml` will be resolved.
"""
function load_artifacts_toml(artifacts_toml::String;
                             pkg_uuid::Union{Base.UUID,Nothing} = nothing)
    artifact_dict = parse_toml(artifacts_toml)

    # Process overrides for this `pkg_uuid`
    process_overrides(artifact_dict, pkg_uuid)
    return artifact_dict
end

"""
    process_overrides(artifact_dict::Dict, pkg_uuid::Base.UUID)

When loading an `Artifacts.toml` file, we must check `Override.toml` files to see if any
of the artifacts within it have been overridden by UUID.  If they have, we honor the
overrides by inspecting the hashes of the targeted artifacts, then overriding them to
point to the given override, punting the actual redirection off to the hash-based
override system.  This does not modify the `artifact_dict` object, it merely dynamically
adds more hash-based overrides as `Artifacts.toml` files that are overridden are loaded.
"""
function process_overrides(artifact_dict::Dict, pkg_uuid::Base.UUID)
    # Insert just-in-time hash overrides by looking up the names of anything we need to
    # override for this UUID, and inserting new overrides for those hashes.
    overrides = load_overrides()
    if haskey(overrides[:UUID], pkg_uuid)
        pkg_overrides = overrides[:UUID][pkg_uuid]

        for name in keys(artifact_dict)
            # Skip names that we're not overriding
            if !haskey(pkg_overrides, name)
                continue
            end

            # If we've got a platform-specific friend, override all hashes:
            if isa(artifact_dict[name], Array)
                for entry in artifact_dict[name]
                    hash = SHA1(entry["git-tree-sha1"])
                    overrides[:hash][hash] = overrides[:UUID][pkg_uuid][name]
                end
            elseif isa(artifact_dict[name], Dict)
                hash = SHA1(artifact_dict[name]["git-tree-sha1"])
                overrides[:hash][hash] = overrides[:UUID][pkg_uuid][name]
            end
        end
    end
    return artifact_dict
end

# If someone tries to call process_overrides() with `nothing`, do exactly that
process_overrides(artifact_dict::Dict, pkg_uuid::Nothing) = nothing

"""
    artifact_meta(name::String, artifacts_toml::String;
                  platform::Platform = Platform(),
                  pkg_uuid::Union{Base.UUID,Nothing}=nothing)

Get metadata about a given artifact (identified by name) stored within the given
`(Julia)Artifacts.toml` file.  If the artifact is platform-specific, use `platform` to choose the
most appropriate mapping.  If none is found, return `nothing`.

!!! compat "Julia 1.3"
    This function requires at least Julia 1.3.
"""
function artifact_meta(name::String, artifacts_toml::String;
                       platform::Platform = Platform(),
                       pkg_uuid::Union{Base.UUID,Nothing}=nothing)
    if !isfile(artifacts_toml)
        return nothing
    end

    # Parse the toml of the artifacts_toml file
    artifact_dict = load_artifacts_toml(artifacts_toml; pkg_uuid=pkg_uuid)
    return artifact_meta(name, artifact_dict, artifacts_toml; platform=platform)
end

function artifact_meta(name::String, artifact_dict::Dict, artifacts_toml::String;
                       platform::Platform = Platform())
    if !haskey(artifact_dict, name)
        return nothing
    end
    meta = artifact_dict[name]

    # If it's an array, find the entry that best matches our current platform
    if isa(meta, Array)
        dl_dict = Dict{Platform,Dict{String,Any}}(unpack_platform(x, name, artifacts_toml) => x for x in meta)
        meta = select_platform(dl_dict, platform)
    # If it's NOT a dict, complain
    elseif !isa(meta, Dict)
        @error("Invalid artifacts file at $(artifacts_toml): artifact '$name' malformed, must be array or dict!")
        return nothing
    end

    # This is such a no-no, we are going to call it out right here, right now.
    if meta !== nothing && !haskey(meta, "git-tree-sha1")
        @error("Invalid artifacts file at $(artifacts_toml): artifact '$name' contains no `git-tree-sha1`!")
        return nothing
    end

    # Return the full meta-dict.
    return meta
end

"""
    artifact_hash(name::String, artifacts_toml::String; platform::Platform = platform_key_abi())

Thin wrapper around `artifact_meta()` to return the hash of the specified, platform-
collapsed artifact.  Returns `nothing` if no mapping can be found.

!!! compat "Julia 1.3"
    This function requires at least Julia 1.3.
"""
function artifact_hash(name::String, artifacts_toml::String;
                       platform::Platform = Platform(),
                       pkg_uuid::Union{Base.UUID,Nothing}=nothing)
    meta = artifact_meta(name, artifacts_toml; platform=platform)
    if meta === nothing
        return nothing
    end

    return SHA1(meta["git-tree-sha1"])
end

"""
    find_artifacts_toml(path::String)

Given the path to a `.jl` file, (such as the one returned by `__source__.file` in a macro
context), find the `(Julia)Artifacts.toml` that is contained within the containing project (if it
exists), otherwise return `nothing`.

!!! compat "Julia 1.3"
    This function requires at least Julia 1.3.
"""
function find_artifacts_toml(path::String)
    if !isdir(path)
        path = dirname(path)
    end

    # Run until we hit the root directory.
    while dirname(path) != path
        for f in artifact_names
            artifacts_toml_path = joinpath(path, f)
            if isfile(artifacts_toml_path)
                return abspath(artifacts_toml_path)
            end
        end

        # Does a `(Julia)Project.toml` file exist here, in the absence of an Artifacts.toml?
        # If so, stop the search as we've probably hit the top-level of this package,
        # and we don't want to escape out into the larger filesystem.
        for f in Base.project_names
            if isfile(joinpath(path, f))
                return nothing
            end
        end

        # Move up a directory
        path = dirname(path)
    end

    # We never found anything, just return `nothing`
    return nothing
end

function _artifact_str(__module__, artifacts_toml, name, artifact_dict, hash)
    if haskey(Base.module_keys, __module__)
        # Process overrides for this UUID, if we know what it is
        process_overrides(artifact_dict, Base.module_keys[__module__].uuid)
    end

    # If the artifact exists, we're in the happy path and we can immediately
    # return the path to the artifact:
    for dir in artifact_paths(hash; honor_overrides=true)
        if isdir(dir)
            return dir
        end
    end

    # If not, we need to download it.  We do some trickery to import Pkg into this
    # Artifacts module so that we only have to do this work if we're sure we need
    # to download something.
    Core.eval(@__MODULE__, :(import Pkg))
    return Pkg.Artifacts.ensure_artifact_installed(name, artifacts_toml)
end

"""
    macro artifact_str(name)

Macro that is used to automatically ensure an artifact is installed, and return its
location on-disk.  Automatically looks the artifact up by name in the project's
`(Julia)Artifacts.toml` file.  Throws an error on inability to install the requested artifact.
If run in the REPL, searches for the toml file starting in the current directory, see
`find_artifacts_toml()` for more.

!!! compat "Julia 1.3"
    This macro requires at least Julia 1.3.
"""
macro artifact_str(name)
    # Load Artifacts.toml at compile time, so that we don't have to use `__source__.file`
    # at runtime, which gets stale if the `.ji` file is relocated.
    srcfile = string(__source__.file)
    if ((isinteractive() && startswith(srcfile, "REPL[")) || (!isinteractive() && srcfile == "none")) && !isfile(srcfile)
        srcfile = pwd()
    end
    local artifacts_toml = find_artifacts_toml(srcfile)
    if artifacts_toml === nothing
        error(string(
            "Cannot locate '(Julia)Artifacts.toml' file when attempting to use artifact '",
            name,
            "' in '",
            __module__,
            "'",
        ))
    end

    # Invalidate calling .ji file if Artifacts.toml file changes
    Base.include_dependency(artifacts_toml)

    local artifact_dict = load_artifacts_toml(artifacts_toml)
    local meta = artifact_meta(name, artifact_dict, artifacts_toml)
    if meta === nothing
        error("Cannot locate artifact '$(name)' in '$(artifacts_toml)'")
    end
    local hash = SHA1(meta["git-tree-sha1"])
    return quote
        _artifact_str($(__module__), $(artifacts_toml), $(esc(name)), $(artifact_dict), $(hash))
    end
end

end # module Artifacts
