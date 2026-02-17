#!/usr/bin/env python3
"""
Bun Standalone Binary Extractor

Extracts embedded JavaScript modules, native binaries, and WASM files from
Bun standalone executables. Supports both Mach-O (__BUN segment) and legacy
(trailer-appended) formats.

Tested against Claude Code v2.1.42 (Bun single-file executable).

Binary Format Reference (from oven-sh/bun src/StandaloneModuleGraph.zig):

  Mach-O layout:
    [Mach-O segments: __TEXT, __DATA_CONST, __DATA, ...]
    [__BUN segment, __bun section]:
      u64            data_length (little-endian)
      [data_length bytes of module graph data]:
        [string/content payloads]
        [bytecode blobs, 128-byte aligned]
        [CompiledModuleGraphFile array]     <- 52 bytes each
        [Offsets struct]                    <- 32 bytes
        [trailer: "\\n---- Bun! ----\\n"]  <- 16 bytes
    [__LINKEDIT segment]

  Offsets struct (32 bytes):
    u64  byte_count
    u32  modules_ptr.offset
    u32  modules_ptr.length
    u32  entry_point_id
    u32  argv_ptr.offset
    u32  argv_ptr.length
    u32  flags

  CompiledModuleGraphFile (52 bytes):
    StringPointer  name                (u32 offset, u32 length)
    StringPointer  contents            (u32 offset, u32 length)
    StringPointer  sourcemap           (u32 offset, u32 length)
    StringPointer  bytecode            (u32 offset, u32 length)
    StringPointer  module_info         (u32 offset, u32 length)
    StringPointer  bytecode_origin_path (u32 offset, u32 length)
    u8  encoding       (0=binary, 1=latin1, 2=utf8)
    u8  loader         (0=file,1=jsx,2=js,3=tsx,4=ts,5=css,6=json,...)
    u8  module_format  (0=none, 1=esm, 2=cjs)
    u8  side           (0=server, 1=client)
"""

import struct
import subprocess
import sys
import os
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Constants ──────────────────────────────────────────────────────────────────

TRAILER = b"\n---- Bun! ----\n"
TRAILER_LEN = 16
OFFSETS_SIZE = 32
MODULE_ENTRY_SIZE = 52
BUNFS_ROOT = "/$bunfs/root/"
BUNFS_ROOT_OLD = "compiled://root/"

ENCODING_NAMES = {0: "binary", 1: "latin1", 2: "utf8"}
LOADER_NAMES = {
    0: "file", 1: "jsx", 2: "js", 3: "tsx", 4: "ts", 5: "css",
    6: "json", 7: "toml", 8: "wasm", 9: "napi", 10: "base64",
    11: "dataurl", 12: "text", 13: "sqlite", 14: "sqlite_embedded",
}
FORMAT_NAMES = {0: "none", 1: "esm", 2: "cjs"}
SIDE_NAMES = {0: "server", 1: "client"}


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class StringPointer:
    offset: int
    length: int


@dataclass
class Offsets:
    byte_count: int
    modules_ptr: StringPointer
    entry_point_id: int
    argv_ptr: StringPointer
    flags: int


@dataclass
class ModuleEntry:
    index: int
    name: str
    raw_name: str
    contents_ptr: StringPointer
    sourcemap_ptr: StringPointer
    bytecode_ptr: StringPointer
    module_info_ptr: StringPointer
    bytecode_origin_path_ptr: StringPointer
    encoding: int
    loader: int
    module_format: int
    side: int

    @property
    def encoding_name(self) -> str:
        return ENCODING_NAMES.get(self.encoding, f"unknown({self.encoding})")

    @property
    def loader_name(self) -> str:
        return LOADER_NAMES.get(self.loader, f"unknown({self.loader})")

    @property
    def format_name(self) -> str:
        return FORMAT_NAMES.get(self.module_format, f"unknown({self.module_format})")

    @property
    def side_name(self) -> str:
        return SIDE_NAMES.get(self.side, f"unknown({self.side})")

    @property
    def is_binary(self) -> bool:
        return self.encoding == 0

    @property
    def file_extension(self) -> str:
        base = Path(self.name).suffix
        if base:
            return base
        loader_ext = {1: ".jsx", 2: ".js", 3: ".tsx", 4: ".ts", 5: ".css",
                      6: ".json", 7: ".toml", 8: ".wasm", 9: ".node", 10: ".b64"}
        return loader_ext.get(self.loader, ".bin")


@dataclass
class BunStandaloneInfo:
    format: str  # "macho" or "trailer"
    data_offset: int  # absolute file offset where module graph data begins
    data_length: int
    offsets: Offsets
    modules: list
    bun_version: Optional[str] = None


# ── Mach-O Parsing ────────────────────────────────────────────────────────────

def find_macho_bun_section(filepath: str) -> Optional[tuple]:
    """Use otool to find __BUN,__bun section offset and size."""
    try:
        result = subprocess.run(
            ["otool", "-l", filepath],
            capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    lines = result.stdout.split("\n")
    in_bun_segment = False
    in_bun_section = False
    section_offset = None
    section_size = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if "segname __BUN" in stripped:
            in_bun_segment = True
        elif in_bun_segment and "sectname __bun" in stripped:
            in_bun_section = True
        elif in_bun_section:
            if stripped.startswith("offset "):
                section_offset = int(stripped.split()[-1])
            elif stripped.startswith("size "):
                section_size = int(stripped.split()[-1], 16)
            if section_offset is not None and section_size is not None:
                return (section_offset, section_size)
        elif in_bun_segment and "segname" in stripped and "__BUN" not in stripped:
            in_bun_segment = False

    return None


# ── Trailer-based Parsing (Linux/Windows fallback) ───────────────────────────

def find_trailer_data(f, file_size: int) -> Optional[tuple]:
    """Find module graph data using the trailer appended to end of file."""
    search_size = min(file_size, 4 * 1024 * 1024)
    f.seek(file_size - search_size)
    tail = f.read(search_size)

    idx = tail.rfind(TRAILER)
    if idx == -1:
        return None

    trailer_abs = (file_size - search_size) + idx

    # Read the total byte count from after the trailer
    f.seek(trailer_abs + TRAILER_LEN)
    total_bytes_raw = f.read(8)
    if len(total_bytes_raw) < 8:
        return None
    total_byte_count = struct.unpack("<Q", total_bytes_raw)[0]

    # Data starts at: trailer_pos - offsets_size - data
    data_start = trailer_abs - OFFSETS_SIZE - total_byte_count
    if data_start < 0:
        return None

    return (data_start, total_byte_count + OFFSETS_SIZE + TRAILER_LEN)


# ── Core Parsing ──────────────────────────────────────────────────────────────

def parse_offsets(data: bytes, offset: int) -> Offsets:
    """Parse the 32-byte Offsets struct."""
    vals = struct.unpack_from("<Q II I II I", data, offset)
    return Offsets(
        byte_count=vals[0],
        modules_ptr=StringPointer(offset=vals[1], length=vals[2]),
        entry_point_id=vals[3],
        argv_ptr=StringPointer(offset=vals[4], length=vals[5]),
        flags=vals[6],
    )


def parse_module_entry(data: bytes, offset: int, index: int) -> ModuleEntry:
    """Parse a 52-byte CompiledModuleGraphFile struct."""
    vals = struct.unpack_from("<II II II II II II BBBB", data, offset)

    name_ptr = StringPointer(offset=vals[0], length=vals[1])

    # Extract name string
    raw_name = ""
    if name_ptr.length > 0 and name_ptr.offset + name_ptr.length <= len(data):
        raw_name = data[name_ptr.offset:name_ptr.offset + name_ptr.length].decode(
            "utf-8", errors="replace"
        )

    # Normalize virtual filesystem paths
    name = raw_name
    if name.startswith(BUNFS_ROOT):
        name = name[len(BUNFS_ROOT):]
    elif name.startswith(BUNFS_ROOT_OLD):
        name = name[len(BUNFS_ROOT_OLD):]

    return ModuleEntry(
        index=index,
        name=name,
        raw_name=raw_name,
        contents_ptr=StringPointer(offset=vals[2], length=vals[3]),
        sourcemap_ptr=StringPointer(offset=vals[4], length=vals[5]),
        bytecode_ptr=StringPointer(offset=vals[6], length=vals[7]),
        module_info_ptr=StringPointer(offset=vals[8], length=vals[9]),
        bytecode_origin_path_ptr=StringPointer(offset=vals[10], length=vals[11]),
        encoding=vals[12],
        loader=vals[13],
        module_format=vals[14],
        side=vals[15],
    )


def extract_bytes(data: bytes, ptr: StringPointer) -> bytes:
    """Extract bytes from the data buffer using a StringPointer."""
    if ptr.length == 0:
        return b""
    end = ptr.offset + ptr.length
    if end > len(data):
        raise ValueError(
            f"Pointer extends beyond buffer: offset={ptr.offset}, "
            f"length={ptr.length}, buffer_size={len(data)}"
        )
    return data[ptr.offset:end]


def find_bun_version(data: bytes) -> Optional[str]:
    """Search for Bun version string in the data."""
    markers = [b"bun build v", b"----- bun meta -----\nBun v"]
    for marker in markers:
        idx = data.find(marker)
        if idx != -1:
            start = idx + len(marker)
            end = data.find(b"\n", start)
            if end != -1 and end - start < 20:
                return data[start:end].decode("utf-8", errors="replace").strip()
    return None


# ── Main Analysis ─────────────────────────────────────────────────────────────

def analyze(filepath: str) -> BunStandaloneInfo:
    """Analyze a Bun standalone binary and extract module graph metadata."""
    file_size = os.path.getsize(filepath)

    with open(filepath, "rb") as f:
        # Try Mach-O __BUN section first
        macho_info = find_macho_bun_section(filepath)
        if macho_info:
            section_offset, section_size = macho_info
            f.seek(section_offset)
            header = f.read(8)
            data_length = struct.unpack("<Q", header)[0]
            data_offset = section_offset + 8
            fmt = "macho"

            # Read full module graph data
            f.seek(data_offset)
            data = f.read(data_length)
        else:
            # Try trailer format
            trailer_info = find_trailer_data(f, file_size)
            if not trailer_info:
                raise ValueError(
                    "Not a Bun standalone executable: no __BUN section or trailer found"
                )
            data_offset, total_size = trailer_info
            f.seek(data_offset)
            data = f.read(total_size)
            data_length = len(data)
            fmt = "trailer"

    # Locate trailer within data
    trailer_idx = data.rfind(TRAILER)
    if trailer_idx == -1:
        raise ValueError("Trailer not found in module graph data")

    # Parse Offsets (32 bytes before trailer)
    offsets_idx = trailer_idx - OFFSETS_SIZE
    if offsets_idx < 0:
        raise ValueError("Offsets struct position is invalid")
    offsets = parse_offsets(data, offsets_idx)

    # Parse module entries
    mod_offset = offsets.modules_ptr.offset
    mod_length = offsets.modules_ptr.length

    if mod_offset + mod_length > len(data):
        raise ValueError(
            f"Module array out of bounds: offset={mod_offset}, "
            f"length={mod_length}, data_size={len(data)}"
        )

    if mod_length % MODULE_ENTRY_SIZE != 0:
        raise ValueError(
            f"Module array length {mod_length} not divisible by "
            f"entry size {MODULE_ENTRY_SIZE}"
        )

    module_count = mod_length // MODULE_ENTRY_SIZE
    modules = []
    for i in range(module_count):
        entry_offset = mod_offset + (i * MODULE_ENTRY_SIZE)
        mod = parse_module_entry(data, entry_offset, i)
        modules.append(mod)

    # Find version
    version = find_bun_version(data)

    return BunStandaloneInfo(
        format=fmt,
        data_offset=data_offset,
        data_length=data_length,
        offsets=offsets,
        modules=modules,
        bun_version=version,
    )


def extract_modules(filepath: str, info: BunStandaloneInfo, output_dir: str,
                    extract_source: bool = True, extract_bytecode: bool = False,
                    extract_sourcemaps: bool = False, module_filter: str = None):
    """Extract module contents to disk."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Read the full data region
    with open(filepath, "rb") as f:
        f.seek(info.data_offset)
        data = f.read(info.data_length)

    manifest = []

    for mod in info.modules:
        if module_filter and module_filter not in mod.name:
            continue

        mod_info = {
            "index": mod.index,
            "name": mod.name,
            "raw_name": mod.raw_name,
            "encoding": mod.encoding_name,
            "loader": mod.loader_name,
            "format": mod.format_name,
            "side": mod.side_name,
            "contents_size": mod.contents_ptr.length,
            "bytecode_size": mod.bytecode_ptr.length,
            "sourcemap_size": mod.sourcemap_ptr.length,
            "is_entry_point": mod.index == info.offsets.entry_point_id,
        }

        # Determine output filename
        safe_name = mod.name.replace("/", os.sep)
        if not safe_name:
            safe_name = f"module_{mod.index}"

        # Extract source contents
        if extract_source and mod.contents_ptr.length > 0:
            try:
                contents = extract_bytes(data, mod.contents_ptr)
                source_path = out / "source" / safe_name
                source_path.parent.mkdir(parents=True, exist_ok=True)
                source_path.write_bytes(contents)
                mod_info["source_path"] = str(source_path)
                print(f"  [source] {safe_name} ({len(contents):,} bytes)")
            except ValueError as e:
                print(f"  [ERROR]  {safe_name}: {e}")
                mod_info["source_error"] = str(e)

        # Extract bytecode
        if extract_bytecode and mod.bytecode_ptr.length > 0:
            try:
                bytecode = extract_bytes(data, mod.bytecode_ptr)
                bc_path = out / "bytecode" / (safe_name + ".jsc")
                bc_path.parent.mkdir(parents=True, exist_ok=True)
                bc_path.write_bytes(bytecode)
                mod_info["bytecode_path"] = str(bc_path)
                print(f"  [bytecd] {safe_name}.jsc ({len(bytecode):,} bytes)")
            except ValueError as e:
                print(f"  [ERROR]  {safe_name} bytecode: {e}")
                mod_info["bytecode_error"] = str(e)

        # Extract sourcemaps
        if extract_sourcemaps and mod.sourcemap_ptr.length > 0:
            try:
                sm = extract_bytes(data, mod.sourcemap_ptr)
                sm_path = out / "sourcemaps" / (safe_name + ".map")
                sm_path.parent.mkdir(parents=True, exist_ok=True)
                sm_path.write_bytes(sm)
                mod_info["sourcemap_path"] = str(sm_path)
                print(f"  [srcmap] {safe_name}.map ({len(sm):,} bytes)")
            except ValueError as e:
                print(f"  [ERROR]  {safe_name} sourcemap: {e}")

        manifest.append(mod_info)

    # Write manifest
    manifest_path = out / "manifest.json"
    with open(manifest_path, "w") as mf:
        json.dump({
            "binary": filepath,
            "format": info.format,
            "bun_version": info.bun_version,
            "data_offset": info.data_offset,
            "data_length": info.data_length,
            "entry_point_id": info.offsets.entry_point_id,
            "flags": info.offsets.flags,
            "module_count": len(info.modules),
            "modules": manifest,
        }, mf, indent=2)
    print(f"\n  Manifest written to {manifest_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def print_info(info: BunStandaloneInfo):
    """Print analysis summary."""
    print(f"\n{'='*72}")
    print(f"  Bun Standalone Binary Analysis")
    print(f"{'='*72}")
    print(f"  Format:          {info.format}")
    print(f"  Bun version:     {info.bun_version or 'unknown'}")
    print(f"  Data offset:     {info.data_offset:#x} ({info.data_offset:,} bytes)")
    print(f"  Data length:     {info.data_length:#x} ({info.data_length:,} bytes)")
    print(f"  Entry point:     module[{info.offsets.entry_point_id}]")
    print(f"  Flags:           {info.offsets.flags:#010b}")
    print(f"  Module count:    {len(info.modules)}")
    print(f"{'='*72}")

    ep = info.offsets.entry_point_id
    total_source = 0
    total_bytecode = 0

    for mod in info.modules:
        marker = " >> " if mod.index == ep else "    "
        print(f"{marker}[{mod.index:2d}] {mod.name}")
        print(f"         contents: {mod.contents_ptr.length:>12,} bytes"
              f"  bytecode: {mod.bytecode_ptr.length:>12,} bytes")
        print(f"         encoding: {mod.encoding_name:<8}"
              f"  loader: {mod.loader_name:<8}"
              f"  format: {mod.format_name:<5}"
              f"  side: {mod.side_name}")
        if mod.sourcemap_ptr.length > 0:
            print(f"         sourcemap: {mod.sourcemap_ptr.length:>11,} bytes")
        if mod.module_info_ptr.length > 0:
            print(f"         module_info: {mod.module_info_ptr.length:>9,} bytes")

        total_source += mod.contents_ptr.length
        total_bytecode += mod.bytecode_ptr.length

    print(f"\n{'─'*72}")
    print(f"  Total source:    {total_source:>12,} bytes ({total_source/1024/1024:.1f} MB)")
    print(f"  Total bytecode:  {total_bytecode:>12,} bytes ({total_bytecode/1024/1024:.1f} MB)")
    print(f"  Total embedded:  {total_source + total_bytecode:>12,} bytes "
          f"({(total_source + total_bytecode)/1024/1024:.1f} MB)")
    print(f"{'─'*72}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Extract modules from Bun standalone executables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s info ./my-app              # Show module listing
  %(prog)s extract ./my-app -o out/   # Extract source files
  %(prog)s extract ./my-app -o out/ --bytecode  # Include JSC bytecode
  %(prog)s extract ./my-app -o out/ --filter claude  # Only matching modules
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # info command
    info_cmd = sub.add_parser("info", help="Show binary analysis and module listing")
    info_cmd.add_argument("binary", help="Path to Bun standalone executable")

    # extract command
    ext_cmd = sub.add_parser("extract", help="Extract embedded modules to disk")
    ext_cmd.add_argument("binary", help="Path to Bun standalone executable")
    ext_cmd.add_argument("-o", "--output", default="./bun_extracted",
                         help="Output directory (default: ./bun_extracted)")
    ext_cmd.add_argument("--bytecode", action="store_true",
                         help="Also extract JSC bytecode blobs")
    ext_cmd.add_argument("--sourcemaps", action="store_true",
                         help="Also extract source maps")
    ext_cmd.add_argument("--filter", default=None,
                         help="Only extract modules whose name contains this string")
    ext_cmd.add_argument("--no-source", action="store_true",
                         help="Skip source extraction (useful with --bytecode only)")

    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"Error: {args.binary} not found", file=sys.stderr)
        sys.exit(1)

    try:
        info = analyze(args.binary)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.command == "info":
        print_info(info)

    elif args.command == "extract":
        print_info(info)
        print(f"Extracting to {args.output}/\n")
        extract_modules(
            args.binary, info, args.output,
            extract_source=not args.no_source,
            extract_bytecode=args.bytecode,
            extract_sourcemaps=args.sourcemaps,
            module_filter=args.filter,
        )
        print("\nDone.")


if __name__ == "__main__":
    main()
