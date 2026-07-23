//===- Pdb2TypeServer.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// MSVC 6.0 `/Zi` writes each translation unit's types into an external
// PDB 2.0 ("JG") type server (a `*.o.pdb` referenced from the object's
// `.debug$T` by an old LF_TYPESERVER/LF_TYPESERVER_ST record). PDB 2.0 is a
// different, older MSF container than the PDB 7.0 ("DS") format the rest of
// LLVM's PDB/MSF libraries assume, so it cannot be opened via PDBFile /
// NativeSession; this file implements a small from-scratch reader for it.
//
// Intra-object TypeIndex references inside the TPI stream are already
// encoded the way a modern object's local .debug$T would encode them
// (`0x1000 + N`, N = the referenced record's 0-based position in the
// stream), so no reindexing is needed -- see the comment on
// readPdb2TypeServerTypes's implementation for the byte-level evidence. The
// one real fix-up needed: named leaf kinds (LF_STRUCTURE, LF_MEMBER,
// LF_ENUM, and siblings) use old "_ST" kind values with a Pascal-style
// (length-prefixed) name instead of the modern kind with a null-terminated
// name; see stFixupFor() in the .cpp for the full set handled.

#ifndef LLD_COFF_PDB2TYPESERVER_H
#define LLD_COFF_PDB2TYPESERVER_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/Allocator.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBufferRef.h"

namespace lld::coff {

// Returns true if `data` looks like a PDB 2.0 ("JG") MSF file, i.e. starts
// with the "Microsoft C/C++ program database 2.00" signature.
bool isPdb2TypeServer(llvm::MemoryBufferRef mb);

// Reads the TPI stream out of a VC6 /Zi PDB 2.0 type server and returns the
// upgraded type-record bytes: named leaf kinds rewritten from old "_ST"
// (Pascal-name) kind values to their modern (null-terminated-name)
// equivalents. TypeIndex references are left untouched -- see the file
// comment above for why no reindexing is needed. The returned bytes are
// allocated out of `alloc` and are a drop-in replacement for what a normal
// object's `.debug$T` content (post consumeDebugMagic) would contain -- i.e.
// suitable for `ObjFile::debugTypes` + `makeTpiSource()`.
llvm::Expected<llvm::ArrayRef<uint8_t>>
readPdb2TypeServerTypes(llvm::MemoryBufferRef mb, llvm::BumpPtrAllocator &alloc);

} // namespace lld::coff

#endif
