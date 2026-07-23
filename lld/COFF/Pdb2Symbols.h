//===- Pdb2Symbols.h --------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// MSVC 6.0 `/Zi` writes each .debug$S section using the old CodeView C11
// signature (same CV_SIGNATURE_C11 = 2 as .debug$T, see Pdb2TypeServer.h):
// a flat, unwrapped sequence of symbol records (no subsection framing, unlike
// modern C13), using old "_ST" (Pascal-name) symbol kinds for the handful of
// record types that carry a name.
//
// An object with more than one function has additional .debug$S sections
// (one per function) that carry no magic at all -- they start directly with
// an S_GPROC32_ST/S_LPROC32_ST record. isBareOldCodeViewSymbols detects
// those.
//
// convertOldCodeViewSymbols rewrites the old-kind records to modern
// equivalents in place. The returned buffer is the same total size and
// layout as the input -- magic present or absent, exactly as given -- since
// this section's existing COFF relocations point at byte offsets counted
// from the section's start (e.g. S_GDATA32_ST's DataOffset/Segment fields);
// nothing here may shift those offsets, including by adding or stripping a
// magic prefix. Callers check isOldCodeViewSymbols/isBareOldCodeViewSymbols
// on whatever SectionChunk::getContents() returns (the override, once one
// is set) to decide whether to treat it as a flat symbol stream instead of
// a subsection array -- see the callers in PDB.cpp.

#ifndef LLD_COFF_PDB2SYMBOLS_H
#define LLD_COFF_PDB2SYMBOLS_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/Allocator.h"
#include "llvm/Support/Error.h"

namespace lld::coff {

// Returns true if `sectionContents` (the raw, unstripped .debug$S section
// bytes) starts with the old CV_SIGNATURE_C11 magic.
bool isOldCodeViewSymbols(llvm::ArrayRef<uint8_t> sectionContents);

// Returns true if `sectionContents` has no magic at all but looks like a
// per-function continuation .debug$S section: starts directly with an
// S_GPROC32_ST/S_LPROC32_ST record whose declared length doesn't overrun
// the buffer.
bool isBareOldCodeViewSymbols(llvm::ArrayRef<uint8_t> sectionContents);

// Converts an old-format .debug$S section's known "_ST" symbol kinds to
// their modern (null-terminated-name) equivalents, and strips the leading
// magic if `sectionContents` has one (per isOldCodeViewSymbols) -- the
// returned buffer is always just the flat symbol stream, whether or not the
// input had a magic prefix. Suitable as a drop-in replacement for the
// section's contents, and every consumer's signal that this chunk is
// old-format and already converted, via ObjFile::getDebugSOverride
// returning non-empty for it.
llvm::Expected<llvm::ArrayRef<uint8_t>>
convertOldCodeViewSymbols(llvm::ArrayRef<uint8_t> sectionContents,
                         llvm::BumpPtrAllocator &alloc);

} // namespace lld::coff

#endif
