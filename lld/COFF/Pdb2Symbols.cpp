//===- Pdb2Symbols.cpp -----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// See Pdb2Symbols.h. A real MSVC 6.0 .debug$S section (surveyed across every
// matched object in this project) uses exactly these old symbol kinds:
//
//   S_OBJNAME_ST  (0x0009) [sig:4][name] -> S_OBJNAME  (0x1101)
//   S_CONSTANT_ST (0x1002) [type:4][value: numeric-leaf][name] -> S_CONSTANT (0x1107)
//   S_UDT_ST      (0x1003) [type:4][name] -> S_UDT      (0x1108)
//   S_LDATA32_ST  (0x1007) [type:4][offset:4][segment:2][name] -> S_LDATA32 (0x110c)
//   S_GDATA32_ST  (0x1008) [type:4][offset:4][segment:2][name] -> S_GDATA32 (0x110d)
//   S_REGISTER_ST (0x1001) [index:4][register:2][name] -> S_REGISTER (0x1106)
//   S_BPREL32_ST  (0x1006) [offset:4][type:4][name] -> S_BPREL32 (0x110b)
//   S_LABEL32_ST  (0x0209) [codeoffset:4][segment:2][flags:1][name] -> S_LABEL32 (0x1105)
//   S_LPROC32_ST  (0x100a) [8 x u32][segment:2][flags:1][name] -> S_LPROC32 (0x110f)
//   S_GPROC32_ST  (0x100b) same shape as S_LPROC32_ST -> S_GPROC32 (0x1110)
//   S_END         (0x0006) -- already the same value in old and new numbering
//                             (no name, no conversion needed)
//   S_COMPILE     (0x0001) -- no modern equivalent exists in LLVM at all (not
//                             even an "_ST" sibling; this predates that
//                             family). Carries only compiler-version text,
//                             nothing structural. Replaced with S_SKIP rather
//                             than guessed at.
//
// Shapes verified against llvm::codeview::SymbolRecordMapping::
// visitKnownRecord for ObjNameSym/ConstantSym/UDTSym/DataSym/RegisterSym/
// BPRelativeSym/LabelSym/ProcSym in SymbolRecordMapping.cpp, and cross-
// checked against real record bytes (struct.unpack, not by hand -- an
// earlier by-hand count of ProcSym's fields looked wrong at first and
// wasn't).

#include "Pdb2Symbols.h"

#include "llvm/DebugInfo/CodeView/CodeView.h"
#include "llvm/DebugInfo/CodeView/RecordSerialization.h"
#include "llvm/Support/Endian.h"

using namespace llvm;
using namespace llvm::codeview;
using namespace llvm::support;

namespace lld::coff {

static constexpr uint32_t cvSignatureC11 = 2;

bool isOldCodeViewSymbols(ArrayRef<uint8_t> sectionContents) {
  return sectionContents.size() >= 4 &&
         support::endian::read32le(sectionContents.data()) == cvSignatureC11;
}

bool isBareOldCodeViewSymbols(ArrayRef<uint8_t> sectionContents) {
  if (sectionContents.size() < 4)
    return false;
  uint16_t length = support::endian::read16le(sectionContents.data());
  uint16_t kind = support::endian::read16le(sectionContents.data() + 2);
  return (kind == S_GPROC32_ST || kind == S_LPROC32_ST) &&
         size_t(2 + length) <= sectionContents.size();
}

// Same numeric-leaf-encoding table as Pdb2TypeServer.cpp's numericLeafSize;
// duplicated rather than shared since it's the only overlap between the two
// files and it's small.
static bool numericLeafSize(uint16_t firstWord, size_t &size) {
  if (firstWord < LF_NUMERIC) {
    size = 2;
    return true;
  }
  switch (firstWord) {
  case LF_CHAR:
    size = 3;
    return true;
  case LF_SHORT:
  case LF_USHORT:
    size = 4;
    return true;
  case LF_LONG:
  case LF_ULONG:
    size = 6;
    return true;
  case LF_REAL32:
    size = 6;
    return true;
  case LF_REAL64:
    size = 10;
    return true;
  case LF_REAL80:
    size = 12;
    return true;
  case LF_REAL128:
    size = 18;
    return true;
  case LF_QUADWORD:
  case LF_UQUADWORD:
    size = 10;
    return true;
  default:
    return false;
  }
}

// Converts a Pascal-style (length-prefixed) name at `nameOffset` to
// null-terminated, in place. Both encodings occupy exactly N+1 bytes for an
// N-character name, so this never changes the record's length. Returns
// false (record left untouched) if the shape doesn't match.
static bool fixupPascalNameDirectAt(MutableArrayRef<uint8_t> rec,
                                    size_t nameOffset) {
  if (nameOffset >= rec.size())
    return false;
  uint8_t nameLen = rec[nameOffset];
  if (nameOffset + 1 + nameLen > rec.size())
    return false;
  uint8_t *name = rec.data() + nameOffset;
  for (uint8_t i = 0; i < nameLen; ++i)
    name[i] = name[i + 1];
  name[nameLen] = 0;
  return true;
}

// As above, but `prefixSize` is followed by a numeric-leaf-encoded value
// (S_CONSTANT's Value) before the name.
static bool fixupPascalNameAfterLeafAt(MutableArrayRef<uint8_t> rec,
                                       size_t prefixSize) {
  if (rec.size() < prefixSize + 3)
    return false;
  size_t numericFieldSize;
  if (!numericLeafSize(support::endian::read16le(rec.data() + prefixSize),
                       numericFieldSize))
    return false;
  return fixupPascalNameDirectAt(rec, prefixSize + numericFieldSize);
}

// Rewrites one old-kind symbol record to its modern equivalent in place.
// Only commits the kind rewrite if the name fixup succeeds, for the same
// reason as Pdb2TypeServer.cpp's stFixupFor loop: a kind tag that doesn't
// match its actual (still Pascal-encoded) name is worse than leaving the
// record as an unrecognized old kind.
static void convertOneSymbol(MutableArrayRef<uint8_t> rec) {
  uint16_t kind = support::endian::read16le(rec.data() + 2);
  switch (kind) {
  case S_OBJNAME_ST: // [len:2][kind:2][sig:4][name]
    if (fixupPascalNameDirectAt(rec, /*len+kind+sig=*/4 + 4))
      support::endian::write16le(rec.data() + 2, uint16_t(S_OBJNAME));
    break;
  case S_CONSTANT_ST: // [len:2][kind:2][type:4][value-leaf][name]
    if (fixupPascalNameAfterLeafAt(rec, /*len+kind+type=*/4 + 4))
      support::endian::write16le(rec.data() + 2, uint16_t(S_CONSTANT));
    break;
  case S_UDT_ST: // [len:2][kind:2][type:4][name]
    if (fixupPascalNameDirectAt(rec, /*len+kind+type=*/4 + 4))
      support::endian::write16le(rec.data() + 2, uint16_t(S_UDT));
    break;
  case S_LDATA32_ST: // [len:2][kind:2][type:4][offset:4][segment:2][name]
    if (fixupPascalNameDirectAt(rec, /*len+kind+type+offset+segment=*/
                               4 + 4 + 4 + 2))
      support::endian::write16le(rec.data() + 2, uint16_t(S_LDATA32));
    break;
  case S_GDATA32_ST: // same shape as S_LDATA32_ST
    if (fixupPascalNameDirectAt(rec, /*len+kind+type+offset+segment=*/
                               4 + 4 + 4 + 2))
      support::endian::write16le(rec.data() + 2, uint16_t(S_GDATA32));
    break;
  case S_REGISTER_ST: // [len:2][kind:2][index:4][register:2][name]
    if (fixupPascalNameDirectAt(rec, /*len+kind+index+register=*/4 + 4 + 2))
      support::endian::write16le(rec.data() + 2, uint16_t(S_REGISTER));
    break;
  case S_BPREL32_ST: // [len:2][kind:2][offset:4][type:4][name]
    if (fixupPascalNameDirectAt(rec, /*len+kind+offset+type=*/4 + 4 + 4))
      support::endian::write16le(rec.data() + 2, uint16_t(S_BPREL32));
    break;
  case S_LABEL32_ST: // [len:2][kind:2][codeoffset:4][segment:2][flags:1][name]
    if (fixupPascalNameDirectAt(rec, /*len+kind+codeoffset+segment+flags=*/
                               4 + 4 + 2 + 1))
      support::endian::write16le(rec.data() + 2, uint16_t(S_LABEL32));
    break;
  case S_LPROC32_ST: // [len:2][kind:2][8 x u32][segment:2][flags:1][name] --
                     // the 8 dwords are Parent,End,Next,CodeSize,DbgStart,
                     // DbgEnd,FunctionType,CodeOffset
    if (fixupPascalNameDirectAt(rec, /*len+kind+8u32+segment+flags=*/
                               4 + 8 * 4 + 2 + 1))
      support::endian::write16le(rec.data() + 2, uint16_t(S_LPROC32));
    break;
  case S_GPROC32_ST: // same shape as S_LPROC32_ST
    if (fixupPascalNameDirectAt(rec, /*len+kind+8u32+segment+flags=*/
                               4 + 8 * 4 + 2 + 1))
      support::endian::write16le(rec.data() + 2, uint16_t(S_GPROC32));
    break;
  case S_COMPILE: // no modern shape exists to convert to; just skip it
    support::endian::write16le(rec.data() + 2, uint16_t(S_SKIP));
    break;
  default:
    break; // unrecognized old kind; leave as-is, downstream treats as opaque
  }
}

Expected<ArrayRef<uint8_t>>
convertOldCodeViewSymbols(ArrayRef<uint8_t> sectionContents,
                          BumpPtrAllocator &alloc) {
  bool hasMagic = isOldCodeViewSymbols(sectionContents);
  assert(hasMagic || isBareOldCodeViewSymbols(sectionContents));

  // Same total size and layout as the input (magic present or absent,
  // exactly as given -- unchanged either way): this section's COFF
  // relocations point at byte offsets counted from the section's start
  // (e.g. S_GDATA32_ST's DataOffset/Segment fields), so nothing here may
  // shift those offsets, including by stripping a magic that was there.
  size_t bodyStart = hasMagic ? 4 : 0;
  uint8_t *out = alloc.Allocate<uint8_t>(sectionContents.size());
  memcpy(out, sectionContents.data(), sectionContents.size());
  MutableArrayRef<uint8_t> body(out + bodyStart,
                               sectionContents.size() - bodyStart);

  size_t pos = 0;
  while (pos + sizeof(RecordPrefix) <= body.size()) {
    uint16_t length = support::endian::read16le(body.data() + pos);
    if (pos + 2 + length > body.size())
      return createStringError("VC6 .debug$S: symbol record overruns "
                               "section at offset " +
                               Twine(pos));
    convertOneSymbol(body.slice(pos, 2 + length));
    pos += 2 + length;
  }

  return ArrayRef<uint8_t>(out, sectionContents.size());
}

} // namespace lld::coff
