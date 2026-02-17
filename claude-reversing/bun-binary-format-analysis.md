# Bun Standalone Module Graph Binary Format

Complete analysis of the serialization format used by `bun build --compile` to embed JavaScript modules into standalone executables.

Source: https://github.com/oven-sh/bun/blob/main/src/StandaloneModuleGraph.zig

## Overview

The StandaloneModuleGraph is a packed binary format that stores compiled JavaScript modules embedded in standalone executables. This allows Bun to create self-contained executables with zero filesystem overhead for embedded modules.

## Core Data Structures

### StandaloneModuleGraph (Main Container)
```zig
pub const StandaloneModuleGraph = struct {
    bytes: []const u8 = "",                          // Raw serialized data buffer
    files: bun.StringArrayHashMap(File),             // Hash map of File entries
    entry_point_id: u32 = 0,                         // Index into files array
    compile_exec_argv: []const u8 = "",              // Command line arguments
    flags: Flags = .{},                              // Configuration flags
};
```

### File Entry
```zig
pub const File = struct {
    name: []const u8 = "",                           // Virtual file path
    loader: bun.options.Loader,                      // File type (js, ts, jsx, tsx, etc.)
    contents: [:0]const u8 = "",                     // Source code (null-terminated)
    sourcemap: LazySourceMap,                        // Lazy-loaded source map
    cached_blob: ?*bun.webcore.Blob = null,         // Runtime blob cache
    encoding: Encoding = .binary,                    // Text encoding type
    wtf_string: bun.String = bun.String.empty,      // Cached WTF string
    bytecode: []u8 = "",                             // JSC bytecode (optional)
    module_info: []u8 = "",                          // ESM metadata (optional)
    bytecode_origin_path: []const u8 = "",          // Path used during bytecode generation
    module_format: ModuleFormat = .none,             // esm/cjs/none
    side: FileSide = .server,                        // server/client
};
```

### CompiledModuleGraphFile (Serialized Module Entry)
```zig
pub const CompiledModuleGraphFile = struct {
    name: Schema.StringPointer = .{},                // 8 bytes (offset + length)
    contents: Schema.StringPointer = .{},            // 8 bytes (offset + length)
    sourcemap: Schema.StringPointer = .{},           // 8 bytes (offset + length)
    bytecode: Schema.StringPointer = .{},            // 8 bytes (offset + length)
    module_info: Schema.StringPointer = .{},         // 8 bytes (offset + length)
    bytecode_origin_path: Schema.StringPointer = .{}, // 8 bytes (offset + length)
    encoding: Encoding = .latin1,                    // 1 byte
    loader: bun.options.Loader = .file,              // 1 byte (varies based on Loader enum size)
    module_format: ModuleFormat = .none,             // 1 byte
    side: FileSide = .server,                        // 1 byte
};
```

**Total size**: 48 bytes + padding to alignment (varies based on platform struct packing)

### StringPointer (Offset + Length Pair)
```zig
pub const StringPointer = extern struct {
    offset: u32 = 0,   // Byte offset into buffer (4 bytes)
    length: u32 = 0,   // Length in bytes (4 bytes)
};
```

**Size**: 8 bytes (guaranteed)
**Alignment**: 4 bytes (u32)

This is an `extern struct`, meaning it matches C ABI layout and is safe to serialize directly.

### Offsets Structure (Footer Metadata)
```zig
pub const Offsets = extern struct {
    byte_count: usize = 0,                          // Platform-dependent (8 bytes on 64-bit)
    modules_ptr: bun.StringPointer = .{},           // 8 bytes (offset + length)
    entry_point_id: u32 = 0,                        // 4 bytes
    compile_exec_argv_ptr: bun.StringPointer = .{}, // 8 bytes (offset + length)
    flags: Flags = .{},                             // 4 bytes
};
```

**Size**: 32 bytes on 64-bit platforms

### Flags (Configuration Bits)
```zig
pub const Flags = packed struct(u32) {
    disable_default_env_files: bool = false,        // 1 bit
    disable_autoload_bunfig: bool = false,          // 1 bit
    disable_autoload_tsconfig: bool = false,        // 1 bit
    disable_autoload_package_json: bool = false,    // 1 bit
    _padding: u28 = 0,                              // 28 bits (reserved)
};
```

**Size**: 4 bytes (packed into u32)

### Enums

```zig
pub const FileSide = enum(u8) {
    server = 0,  // Server-side code
    client = 1,  // Client-side code
};

pub const Encoding = enum(u8) {
    binary = 0,  // Raw bytes
    latin1 = 1,  // Latin-1 text (default for JS)
    utf8 = 2,    // UTF-8 (reserved, not yet used)
};

pub const ModuleFormat = enum(u8) {
    none = 0,    // Not a module
    esm = 1,     // ES Module
    cjs = 2,     // CommonJS
};
```

## Binary Layout

### Overall File Structure

```
┌─────────────────────────────────────────┐
│  Executable Binary (PE/Mach-O/ELF)     │
│  (existing executable data)             │
├─────────────────────────────────────────┤
│  String Data Payload                    │  ← All string data referenced by StringPointers
│  (variable length)                      │
├─────────────────────────────────────────┤
│  CompiledModuleGraphFile Array          │  ← Array of module entries
│  (module_count × sizeof(Module))        │
├─────────────────────────────────────────┤
│  Offsets Structure                      │  ← 32 bytes (on 64-bit)
│  (32 bytes)                             │
├─────────────────────────────────────────┤
│  Trailer: "\n---- Bun! ----\n"         │  ← 16 bytes (validation marker)
│  (16 bytes)                             │
└─────────────────────────────────────────┘
```

### Platform-Specific Embedding

#### Mach-O (macOS)
- Data embedded in a dedicated segment
- 8-byte size header at start
- Memory-mapped at page-aligned address (128-byte aligned)
- Data starts at offset 8 from section start

#### PE (Windows)
- Data embedded in a dedicated section
- 8-byte size header at start
- Section is memory-mapped at page-aligned address
- Data starts at offset 8 from section start

#### ELF (Linux)
- Data appended to the end of executable
- Read into heap-allocated buffer at runtime
- No special section header offset considerations

### Detailed Data Layout

```
Offset   Size    Field
------   ----    -----
[String Data Payload - variable length]
  All string data for names, contents, sourcemaps, bytecode, etc.
  Referenced by StringPointer (offset + length) pairs

[CompiledModuleGraphFile Array]
  For each module (48+ bytes per entry):
    +0     8      name: StringPointer
    +8     8      contents: StringPointer
    +16    8      sourcemap: StringPointer
    +24    8      bytecode: StringPointer
    +32    8      module_info: StringPointer
    +40    8      bytecode_origin_path: StringPointer
    +48    1      encoding: u8
    +49    1      loader: u8 (varies based on Loader enum)
    +50    1      module_format: u8
    +51    1      side: u8
    [padding to alignment]

[Offsets Structure - 32 bytes on 64-bit]
    +0     8      byte_count: usize
    +8     8      modules_ptr: StringPointer
    +16    4      entry_point_id: u32
    +20    8      compile_exec_argv_ptr: StringPointer
    +28    4      flags: Flags (packed u32)

[Trailer - 16 bytes]
    "\n---- Bun! ----\n"
```

## Serialization Process (toBytes)

### Step 1: Calculate Total Capacity

```zig
var string_builder = bun.StringBuilder{};
for (output_files) |*output_file| {
    string_builder.countZ(output_file.dest_path);
    string_builder.countZ(prefix);
    // Add sizes for contents, sourcemaps, bytecode, etc.
}
string_builder.cap += @sizeOf(CompiledModuleGraphFile) * output_files.len;
string_builder.cap += trailer.len;  // 16 bytes
string_builder.cap += 16;           // Extra padding
string_builder.cap += @sizeOf(Offsets);  // 32 bytes on 64-bit
string_builder.countZ(compile_exec_argv);
try string_builder.allocate(allocator);
```

### Step 2: Build String Payload and Module List

For each output file:

1. **Handle Bytecode (with special alignment)**:
   ```zig
   // Bytecode must be aligned to 128 bytes for JSC cache
   const target_mod: usize = 128 - @sizeOf(u64); // = 120
   const current_mod = current_offset % 128;
   const padding = if (current_mod <= target_mod)
       target_mod - current_mod
   else
       128 - current_mod + target_mod;

   // Zero padding bytes for deterministic output
   @memset(writable[0..padding], 0);
   string_builder.len += padding;

   // Copy bytecode
   const aligned_offset = string_builder.len;
   @memcpy(writable_after_padding[0..bytecode.len], bytecode);
   const len = bytecode.len + @min(unaligned_space.len, 128);
   string_builder.len += len;

   bytecode_ptr = StringPointer{
       .offset = @truncate(aligned_offset),
       .length = @truncate(len)
   };
   ```

   **Why 120-byte offset?**
   - On PE/Mach-O: Section has 8-byte size header
   - Section is page-aligned (128-byte boundary)
   - Data starts 8 bytes after section start
   - To align bytecode: `(offset + 8) % 128 == 0`
   - Therefore: `offset % 128 == 120`

2. **Append module_info (if present)**:
   ```zig
   const offset = string_builder.len;
   @memcpy(writable[0..mi_bytes.len], mi_bytes);
   string_builder.len += mi_bytes.len;
   module_info_ptr = StringPointer{
       .offset = @truncate(offset),
       .length = @truncate(mi_bytes.len)
   };
   ```

3. **Append module contents**:
   ```zig
   contents_ptr = string_builder.appendCountZ(output_file.value.buffer.bytes);
   ```

4. **Process source map** (see Source Map Serialization below)

5. **Create module entry**:
   ```zig
   var module = CompiledModuleGraphFile{
       .name = string_builder.fmtAppendCountZ("{s}{s}", .{ prefix, dest_path }),
       .loader = output_file.loader,
       .contents = contents_ptr,
       .encoding = switch (output_file.loader) {
           .js, .jsx, .ts, .tsx => .latin1,
           else => .binary,
       },
       .module_format = if (output_file.loader.isJavaScriptLike())
           switch (output_format) {
               .cjs => .cjs,
               .esm => .esm,
               else => .none,
           }
       else
           .none,
       .bytecode = bytecode_ptr,
       .module_info = module_info_ptr,
       .bytecode_origin_path = bytecode_origin_path_ptr,
       .side = switch (output_file.side orelse .server) {
           .server => .server,
           .client => .client,
       },
   };
   modules.appendAssumeCapacity(module);
   ```

### Step 3: Append Metadata

```zig
// Create offsets structure
const offsets = Offsets{
    .entry_point_id = @as(u32, @truncate(entry_point_id.?)),
    .modules_ptr = string_builder.appendCount(std.mem.sliceAsBytes(modules.items)),
    .compile_exec_argv_ptr = string_builder.appendCountZ(compile_exec_argv),
    .byte_count = string_builder.len,
    .flags = flags,
};

// Append offsets struct
_ = string_builder.append(std.mem.asBytes(&offsets));

// Append trailer
_ = string_builder.append(trailer);  // "\n---- Bun! ----\n"

return string_builder.ptr.?[0..string_builder.len];
```

## Deserialization Process (fromBytes)

### Step 1: Parse Offsets

```zig
pub fn fromBytes(allocator: std.mem.Allocator, raw_bytes: []u8, offsets: Offsets) !StandaloneModuleGraph
```

The `offsets` parameter is read from the end of the executable:
- Last 16 bytes: trailer (validation)
- Previous 32 bytes: Offsets struct
- Use `offsets.byte_count` to determine total data size

### Step 2: Parse Module List

```zig
const modules_list_bytes = sliceTo(raw_bytes, offsets.modules_ptr);
const modules_list: []align(1) const CompiledModuleGraphFile =
    std.mem.bytesAsSlice(CompiledModuleGraphFile, modules_list_bytes);

if (offsets.entry_point_id > modules_list.len) {
    return error.@"Corrupted module graph: entry point ID is greater than module list count";
}
```

### Step 3: Reconstruct File Entries

```zig
var modules = bun.StringArrayHashMap(File).init(allocator);
try modules.ensureTotalCapacity(modules_list.len);

for (modules_list) |module| {
    modules.putAssumeCapacity(
        sliceToZ(raw_bytes, module.name),
        File{
            .name = sliceToZ(raw_bytes, module.name),
            .loader = module.loader,
            .contents = sliceToZ(raw_bytes, module.contents),
            .sourcemap = if (module.sourcemap.length > 0)
                .{ .serialized = .{
                    .bytes = @alignCast(sliceTo(raw_bytes, module.sourcemap)),
                } }
            else
                .none,
            .bytecode = if (module.bytecode.length > 0)
                @constCast(sliceTo(raw_bytes, module.bytecode))
            else
                &.{},
            .module_info = if (module.module_info.length > 0)
                @constCast(sliceTo(raw_bytes, module.module_info))
            else
                &.{},
            .bytecode_origin_path = if (module.bytecode_origin_path.length > 0)
                sliceToZ(raw_bytes, module.bytecode_origin_path)
            else
                "",
            .module_format = module.module_format,
            .side = module.side,
        },
    );
}

modules.lockPointers(); // Make pointers stable forever
```

### Helper Functions

```zig
fn sliceTo(bytes: []const u8, ptr: bun.StringPointer) []const u8 {
    if (ptr.length == 0) return "";
    return bytes[ptr.offset..][0..ptr.length];
}

fn sliceToZ(bytes: []const u8, ptr: bun.StringPointer) [:0]const u8 {
    if (ptr.length == 0) return "";
    return bytes[ptr.offset..][0..ptr.length :0];
}
```

### Step 4: Create Graph

```zig
return StandaloneModuleGraph{
    .bytes = raw_bytes[0..offsets.byte_count],
    .files = modules,
    .entry_point_id = offsets.entry_point_id,
    .compile_exec_argv = sliceToZ(raw_bytes, offsets.compile_exec_argv_ptr),
    .flags = offsets.flags,
};
```

## Source Map Serialization

Source maps are serialized in a compressed format to reduce executable size.

### SerializedSourceMap Structure

```zig
pub const SerializedSourceMap = struct {
    bytes: []const u8,

    pub const Header = extern struct {
        source_files_count: u32,  // Number of source files
        map_bytes_length: u32,    // Length of VLQ mapping data
    };
};
```

### Binary Layout

```
Offset   Size                           Field
------   ----                           -----
+0       8                              Header (source_files_count + map_bytes_length)
+8       source_files_count × 8         Source file name pointers (StringPointer array)
+N       source_files_count × 8         Compressed source content pointers (StringPointer array)
+M       map_bytes_length               VLQ mapping data (uncompressed)
+P       variable                       String payload (file names + compressed sources)
```

### Accessor Methods

```zig
pub fn header(map: SerializedSourceMap) *align(1) const Header {
    return @ptrCast(map.bytes.ptr);
}

pub fn mappingVLQ(map: SerializedSourceMap) []const u8 {
    const head = map.header();
    const start = @sizeOf(Header) + head.source_files_count * @sizeOf(StringPointer) * 2;
    return map.bytes[start..][0..head.map_bytes_length];
}

pub fn sourceFileNames(map: SerializedSourceMap) []align(1) const StringPointer {
    const head = map.header();
    return @as([*]align(1) const StringPointer, @ptrCast(map.bytes[@sizeOf(Header)..]))[0..head.source_files_count];
}

fn compressedSourceFiles(map: SerializedSourceMap) []align(1) const StringPointer {
    const head = map.header();
    return @as([*]align(1) const StringPointer, @ptrCast(map.bytes[@sizeOf(Header)..]))[head.source_files_count..][0..head.source_files_count];
}
```

### Serialization from JSON Source Map

```zig
pub fn serializeJsonSourceMapForStandalone(
    header_list: *std.array_list.Managed(u8),
    string_payload: *std.array_list.Managed(u8),
    arena: std.mem.Allocator,
    json_source: []const u8,
) !void
```

**Process**:

1. **Parse JSON source map**:
   - Extract `mappings` (VLQ string)
   - Extract `sources` (file paths)
   - Extract `sourcesContent` (source code)

2. **Write header**:
   ```zig
   try out.writeInt(u32, sources_paths.items.len, .little);
   try out.writeInt(u32, @intCast(map_vlq.len), .little);
   ```

3. **Write source file name pointers**:
   ```zig
   for (sources_paths.items.slice()) |item| {
       const decoded = try item.data.e_string.stringCloned(arena);
       const offset = string_payload.items.len;
       try string_payload.appendSlice(decoded);

       const slice = bun.StringPointer{
           .offset = @intCast(offset + string_payload_start_location),
           .length = @intCast(string_payload.items.len - offset),
       };
       try out.writeInt(u32, slice.offset, .little);
       try out.writeInt(u32, slice.length, .little);
   }
   ```

4. **Write compressed source content pointers**:
   ```zig
   for (sources_content.items.slice()) |item| {
       const utf8 = try item.data.e_string.stringCloned(arena);
       const offset = string_payload.items.len;

       const bound = bun.zstd.compressBound(utf8.len);
       try string_payload.ensureUnusedCapacity(bound);

       const compressed_result = bun.zstd.compress(unused, utf8, 1);
       string_payload.items.len += compressed_result.success;

       const slice = bun.StringPointer{
           .offset = @intCast(offset + string_payload_start_location),
           .length = @intCast(string_payload.items.len - offset),
       };
       try out.writeInt(u32, slice.offset, .little);
       try out.writeInt(u32, slice.length, .little);
   }
   ```

5. **Write VLQ mapping data** (uncompressed):
   ```zig
   try out.writeAll(map_vlq);
   ```

### Deserialization (Lazy Loading)

```zig
pub const LazySourceMap = union(enum) {
    serialized: SerializedSourceMap,
    parsed: *SourceMap.ParsedSourceMap,
    none,
};

pub fn load(this: *LazySourceMap) ?*SourceMap.ParsedSourceMap {
    init_lock.lock();
    defer init_lock.unlock();

    return switch (this.*) {
        .none => null,
        .parsed => |map| map,
        .serialized => |serialized| {
            // Parse VLQ mappings
            var stored = switch (SourceMap.Mapping.parse(
                bun.default_allocator,
                serialized.mappingVLQ(),
                null,
                std.math.maxInt(i32),
                std.math.maxInt(i32),
                .{},
            )) {
                .success => |x| x,
                .fail => {
                    this.* = .none;
                    return null;
                },
            };

            // Allocate arrays for file names and decompressed contents
            const source_files = serialized.sourceFileNames();
            const slices = bun.handleOom(bun.default_allocator.alloc(?[]u8, source_files.len * 2));
            const file_names: [][]const u8 = @ptrCast(slices[0..source_files.len]);
            const decompressed_contents_slice = slices[source_files.len..][0..source_files.len];

            for (file_names, source_files) |*dest, src| {
                dest.* = src.slice(serialized.bytes);
            }
            @memset(decompressed_contents_slice, null);

            const data = bun.new(SerializedSourceMap.Loaded, .{
                .map = serialized,
                .decompressed_files = decompressed_contents_slice,
            });

            stored.external_source_names = file_names;
            stored.underlying_provider = .{ .data = @truncate(@intFromPtr(data)), .load_hint = .none, .kind = .zig };
            stored.is_standalone_module_graph = true;

            const parsed = bun.new(SourceMap.ParsedSourceMap, stored);
            parsed.ref(); // never free
            this.* = .{ .parsed = parsed };
            return parsed;
        },
    };
}
```

### Decompression (On-Demand)

```zig
pub fn sourceFileContents(this: Loaded, index: usize) ?[]const u8 {
    if (this.decompressed_files[index]) |decompressed| {
        return if (decompressed.len == 0) null else decompressed;
    }

    const compressed_codes = this.map.compressedSourceFiles();
    const compressed_file = compressed_codes[@intCast(index)].slice(this.map.bytes);
    const size = bun.zstd.getDecompressedSize(compressed_file);

    const bytes = bun.handleOom(bun.default_allocator.alloc(u8, size));
    const result = bun.zstd.decompress(bytes, compressed_file);

    if (result == .err) {
        bun.Output.warn("Source map decompression error: {s}", .{result.err});
        bun.default_allocator.free(bytes);
        this.decompressed_files[index] = "";
        return null;
    }

    const data = bytes[0..result.success];
    this.decompressed_files[index] = data;
    return data;
}
```

## Virtual Path System

To prevent filesystem access for embedded modules, Bun uses special virtual path prefixes.

### Base Paths

```zig
pub const base_path = switch (Environment.os) {
    .windows => "B:\\~BUN\\",
    else => "/$bunfs/",
};
```

**Why these paths?**
- **8 characters**: Fast 64-bit CPU comparisons
- **`$` character**: Unlikely to collide with real paths
- **Windows**: Needs drive letter for valid file URLs
  - `B:` drive (for "Bun", less likely to collide)

### Public Path (for URLs)

```zig
pub const base_public_path = targetBasePublicPath(Environment.os, "");

pub fn targetBasePublicPath(target: Environment.OperatingSystem, comptime suffix: [:0]const u8) [:0]const u8 {
    return switch (target) {
        .windows => "B:/~BUN/" ++ suffix,  // Forward slashes for URLs
        else => "/$bunfs/" ++ suffix,
    };
}
```

### Path Validation

```zig
pub fn isBunStandaloneFilePath(str: []const u8) bool {
    if (Environment.isWindows) {
        // On Windows, remove NT path prefixes before checking
        const canonicalized = strings.withoutNTPrefix(u8, str);
        return isBunStandaloneFilePathCanonicalized(canonicalized);
    }
    return isBunStandaloneFilePathCanonicalized(str);
}

pub fn isBunStandaloneFilePathCanonicalized(str: []const u8) bool {
    return bun.strings.hasPrefixComptime(str, base_path) or
        (Environment.isWindows and bun.strings.hasPrefixComptime(str, base_public_path));
}
```

## Entry Point Resolution

```zig
pub fn entryPoint(this: *const StandaloneModuleGraph) *File {
    return &this.files.values()[this.entry_point_id];
}
```

The entry point is stored as an index into the files array. During serialization, the first server-side JavaScript file with `output_kind == .@"entry-point"` becomes the entry point.

## Module Lookup

### Find by Path

```zig
pub fn find(this: *const StandaloneModuleGraph, name: []const u8) ?*File {
    if (!isBunStandaloneFilePath(name)) {
        return null;
    }
    return this.findAssumeStandalonePath(name);
}

pub fn findAssumeStandalonePath(this: *const StandaloneModuleGraph, name: []const u8) ?*File {
    if (Environment.isWindows) {
        var normalized_buf: bun.PathBuffer = undefined;
        const input = strings.withoutNTPrefix(u8, name);
        const normalized = bun.path.platformToPosixBuf(u8, input, &normalized_buf);
        return this.files.getPtr(normalized);
    }
    return this.files.getPtr(name);
}
```

### Stat Support

```zig
pub fn stat(this: *const StandaloneModuleGraph, name: []const u8) ?bun.Stat {
    const file = this.find(name) orelse return null;
    return file.stat();
}

// In File struct:
pub fn stat(this: *const File) bun.Stat {
    var result = std.mem.zeroes(bun.Stat);
    result.size = @intCast(this.contents.len);
    result.mode = bun.S.IFREG | 0o644;
    return result;
}
```

## Platform-Specific Data Retrieval

### macOS (Mach-O)

```zig
const Macho = struct {
    pub extern "C" fn Bun__getStandaloneModuleGraphMachoLength() ?*align(1) u64;

    pub fn getData() ?[]const u8 {
        if (Bun__getStandaloneModuleGraphMachoLength()) |length| {
            if (length.* < 8) {
                return null;
            }

            // BlobHeader has 8 bytes size (u64), so data starts at offset 8.
            const data_offset = @sizeOf(u64);
            const slice_ptr: [*]const u8 = @ptrCast(length);
            return slice_ptr[data_offset..][0..length.*];
        }

        return null;
    }
};
```

### Windows (PE)

```zig
const PE = struct {
    pub extern "C" fn Bun__getStandaloneModuleGraphPELength() u64;
    pub extern "C" fn Bun__getStandaloneModuleGraphPEData() ?[*]u8;

    pub fn getData() ?[]const u8 {
        const length = Bun__getStandaloneModuleGraphPELength();
        if (length == 0) return null;

        const data_ptr = Bun__getStandaloneModuleGraphPEData() orelse return null;
        return data_ptr[0..length];
    }
};
```

### Linux (ELF) - Read from End of Executable

```zig
const self_exe = openSelf() catch return null;
defer self_exe.close();

// Read last 4096 bytes of executable
var trailer_bytes: [4096]u8 = undefined;
std.posix.lseek_END(self_exe.cast(), -4096) catch return null;

var read_amount: usize = 0;
while (read_amount < trailer_bytes.len) {
    switch (Syscall.read(self_exe, trailer_bytes[read_amount..])) {
        .result => |read| {
            if (read == 0) return null;
            read_amount += read;
        },
        .err => return null,
    }
}

// Find trailer and offsets
var end = @as([]u8, &trailer_bytes).ptr + read_amount - @sizeOf(usize);
const total_byte_count: usize = @as(usize, @bitCast(end[0..8].*));

end -= trailer.len;
if (!bun.strings.hasPrefixComptime(end[0..trailer.len], trailer)) {
    return null; // Invalid trailer
}

end -= @sizeOf(Offsets);
const offsets: Offsets = std.mem.bytesAsValue(Offsets, end[0..@sizeOf(Offsets)]).*;

// Read full data
var to_read = try bun.default_allocator.alloc(u8, offsets.byte_count);
std.posix.lseek_END(self_exe.cast(), -@as(i64, @intCast(offset_from_end + offsets.byte_count))) catch return null;

var remain = to_read;
while (remain.len > 0) {
    switch (Syscall.read(self_exe, remain)) {
        .result => |read| {
            if (read == 0) return null;
            remain = remain[read..];
        },
        .err => {
            bun.default_allocator.free(to_read);
            return null;
        },
    }
}

return try fromBytesAlloc(allocator, to_read, offsets);
```

## Magic Numbers and Constants

```zig
const trailer = "\n---- Bun! ----\n";  // 16 bytes - validation marker
```

**No version number**: The format currently has no explicit version field. Changes to the format would require updating both serialization and deserialization code.

## Bytecode Alignment Details

### Why 128-byte Alignment?

JavaScriptCore (JSC) requires bytecode to be aligned for cache deserialization. The cache expects bytecode at specific memory boundaries.

### Platform-Specific Considerations

#### PE/Mach-O
```
Section/Segment Memory Layout:
┌─────────────────────────────────┐
│  Section Start (page-aligned)   │  ← 128-byte boundary
├─────────────────────────────────┤
│  Size Header (u64)              │  ← 8 bytes
├─────────────────────────────────┤
│  Module Graph Data Starts Here  │  ← offset 8 from section start
│  ...                            │
│  Padding to offset 120          │
├─────────────────────────────────┤
│  Bytecode Starts Here           │  ← offset 120 (== -8 mod 128)
│  (128-byte aligned in memory)   │
└─────────────────────────────────┘

When loaded in memory:
- Section at address A (128-byte aligned)
- Data at address A + 8
- Bytecode at address A + 8 + 120 = A + 128
- A + 128 is 128-byte aligned ✓
```

#### ELF
```
Heap Buffer Layout:
┌─────────────────────────────────┐
│  Buffer Start (allocator-aligned)│  ← May be 128-byte aligned
├─────────────────────────────────┤
│  Module Graph Data Starts Here  │  ← No header offset
│  ...                            │
│  Padding to offset 120          │
├─────────────────────────────────┤
│  Bytecode Starts Here           │  ← offset 120
└─────────────────────────────────┘

If buffer is 128-aligned:
- Buffer at address B (128-byte aligned)
- Bytecode at B + 120
- (B + 120) % 128 = 120 (not aligned)

But this is acceptable because:
1. ELF doesn't guarantee section alignment in memory
2. The 120-byte offset is a safe fallback
3. Extra padding is acceptable overhead
```

### Alignment Calculation

```zig
const target_mod: usize = 128 - @sizeOf(u64); // 120 = accounts for 8-byte header
const current_mod = current_offset % 128;
const padding = if (current_mod <= target_mod)
    target_mod - current_mod
else
    128 - current_mod + target_mod;

// Zero padding for deterministic output
@memset(writable[0..padding], 0);
string_builder.len += padding;
```

**Examples**:
- `current_offset = 0`: `padding = 120` → bytecode at 120
- `current_offset = 50`: `padding = 70` → bytecode at 120
- `current_offset = 121`: `padding = 127` → bytecode at 248 (121 + 127)

## Bytecode Cache Matching

For bytecode cache to work, the `bytecode_origin_path` must match exactly at runtime:

```zig
bytecode_origin_path: StringPointer = if (output_file.bytecode_index != std.math.maxInt(u32))
    string_builder.appendCountZ(output_files[output_file.bytecode_index].dest_path)
else
    .{};
```

The path includes the virtual prefix (e.g., `B:/~BUN/root/app.js`), ensuring deterministic cache hits.

## String Builder Utility

The serialization process uses a `StringBuilder` that supports:

```zig
// Count (reserve space)
string_builder.countZ(str);  // Reserve space for null-terminated string

// Append and get StringPointer
const ptr = string_builder.appendCountZ(str);
const ptr = string_builder.fmtAppendCountZ("{s}{s}", .{ prefix, dest_path });

// Append binary data
const ptr = string_builder.appendCount(bytes);
const ptr = string_builder.addConcat(&.{ header, payload });

// Direct append
_ = string_builder.append(bytes);

// Get writable buffer
const writable = string_builder.writable();
```

## Error Handling

### Validation Checks

```zig
// During deserialization:
if (offsets.entry_point_id > modules_list.len) {
    return error.@"Corrupted module graph: entry point ID is greater than module list count";
}

// Trailer validation:
if (!bun.strings.eqlComptime(trailer_bytes, trailer)) {
    Output.debugWarn("bun standalone module graph has invalid trailer", .{});
    return null;
}

// Size sanity check:
if (total_byte_count > std.math.maxInt(u32) or total_byte_count < 4096) {
    return null;
}
```

### Built-in Executable Detection

To avoid overhead, Bun skips loading module graphs from built-in executables:

```zig
fn isBuiltInExe(comptime T: type, argv0: []const T) bool {
    if (argv0.len == 0) return false;

    if (argv0.len == 3) {
        if (bun.strings.eqlComptimeCheckLenWithType(T, argv0, "bun", false)) {
            return true;
        }
    }

    if (argv0.len == 4) {
        if (bun.strings.eqlComptimeCheckLenWithType(T, argv0, "bunx", false)) {
            return true;
        }
        if (bun.strings.eqlComptimeCheckLenWithType(T, argv0, "node", false)) {
            return true;
        }
    }

    return false;
}
```

## Memory Management

### Pointer Stability

After deserialization, pointers must remain stable:

```zig
modules.lockPointers(); // make the pointers stable forever
```

This ensures that `File` structs can safely hold references to data in the `bytes` buffer.

### Reference Counting

Source maps and blobs are reference-counted to prevent premature deallocation:

```zig
// Source map
parsed.ref(); // never free
this.* = .{ .parsed = parsed };

// Blob store
store.ref(); // make it never free
```

## Complete Example: Reading a Standalone Binary

```zig
// 1. Open the executable
const graph_ptr = try StandaloneModuleGraph.load(allocator);
if (graph_ptr == null) {
    // Not a standalone executable
    return;
}

// 2. Access the entry point
const entry = graph_ptr.entryPoint();
std.debug.print("Entry point: {s}\n", .{entry.name});
std.debug.print("Module format: {s}\n", .{@tagName(entry.module_format)});

// 3. Find a module by path
if (graph_ptr.find("/$bunfs/root/utils.js")) |file| {
    std.debug.print("Found module: {s}\n", .{file.contents});
}

// 4. Access bytecode (if present)
if (entry.bytecode.len > 0) {
    std.debug.print("Has bytecode: {} bytes\n", .{entry.bytecode.len});
}

// 5. Load source map (lazy)
if (entry.sourcemap.load()) |sourcemap| {
    std.debug.print("Source map loaded\n", .{});
}
```

## Summary of Key Points

1. **Binary Format**: Data is stored as a byte array with StringPointer offsets
2. **Platform-Specific**: Different embedding strategies for PE, Mach-O, and ELF
3. **Bytecode Alignment**: 128-byte alignment with 120-byte offset for JSC cache
4. **String Pointers**: 8-byte (offset + length) pairs reference data in buffer
5. **Source Maps**: Compressed with ZSTD, lazy-loaded on demand
6. **Virtual Paths**: `/$bunfs/` (Unix) or `B:\~BUN\` (Windows) prevent filesystem access
7. **No Versioning**: Format has no explicit version field (yet)
8. **Trailer Validation**: `"\n---- Bun! ----\n"` marker ensures validity
9. **Module Formats**: Supports ESM, CJS, and non-module files
10. **Server/Client Split**: Files tagged for server or client-side execution

## References

- Source: [StandaloneModuleGraph.zig](https://github.com/oven-sh/bun/blob/main/src/StandaloneModuleGraph.zig)
- Related: [api/schema.zig](https://github.com/oven-sh/bun/blob/main/src/api/schema.zig) - StringPointer definition
