//===- Pdb2TypeServer.cpp -------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// See Pdb2TypeServer.h for the format background. Layout notes (all
// little-endian), reverse-engineered against real VC6 /Zi *.o.pdb files:
//
// SuperBlock (fixed offsets from file start):
//   0x00  44-byte text signature "Microsoft C/C++ program database 2.00\r\n"
//         followed by 0x1a 'J' 'G' 0x00 0x00.
//   0x2C  u32 pageSize            (observed 0x1000)
//   0x30  u16 startPage           (unused here)
//   0x32  u16 filePages           (unused here)
//   0x34  u32 rootSize            (byte size of the root/stream-directory
//                                  stream)
//   0x38  u32 reserved
//   0x3C  u16[ceil(rootSize/pageSize)]  page numbers holding the root stream
//
// Root stream ("stream directory"), once reassembled from its pages:
//   u32 numStreams
//   numStreams * { u32 size; u32 reserved; }     -- per-stream byte size
//   then, for every stream with size != 0 (in stream-index order), that
//   stream's page numbers as u16s, ceil(size/pageSize) of them.
//
// Stream #2 is the TPI (types) stream. Its own header is a fixed 0x38 (56)
// bytes; empirically:
//   0x00  u32 version           (observed 19961031)
//   0x04  u32 typeIndexBegin    (observed 56 -- NOT the modern 0x1000)
//   0x08  u32 typeIndexEnd
//   0x10  u32 typeRecordBytes   (byte length of the record array that
//                                follows the header; verified to exactly
//                                match "TPI stream size - 56" on samples)
// Bytes [0x38, 0x38+typeRecordBytes) are then a plain, tightly-packed
// CVTypeArray -- [u16 length][u16 leaf][...body...] repeated, length not
// including itself. Leaf kinds without an embedded name (LF_MODIFIER,
// LF_POINTER, LF_ARGLIST, LF_PROCEDURE, LF_FIELDLIST itself, ...) use
// ordinary *modern* (0x1000+) kind values and field layouts. Leaf kinds that
// DO carry a name (LF_STRUCTURE/CLASS/UNION, LF_MEMBER, and siblings) use
// the old "_ST" kind values instead (e.g. LF_STRUCTURE_ST = 0x1005, not
// modern LF_STRUCTURE = 0x1505) with an otherwise-identical field layout,
// except the trailing name is Pascal-style length-prefixed rather than
// null-terminated. See stFixupFor() below for the kinds this reader
// recognizes and rewrites to modern form.
// Stream #3 (conventionally DBI/symbols) is empty in every sample, matching
// "type server PDBs do not contain symbols" (see DebugTypes.cpp).

#include "Pdb2TypeServer.h"

#include "llvm/DebugInfo/CodeView/CVRecord.h"
#include "llvm/DebugInfo/CodeView/CodeView.h"
#include "llvm/DebugInfo/CodeView/RecordSerialization.h"
#include "llvm/DebugInfo/CodeView/TypeIndex.h"
#include "llvm/Support/Endian.h"

using namespace llvm;
using namespace llvm::codeview;
using namespace llvm::support;

namespace lld::coff {

static const char pdb2Magic[] = "Microsoft C/C++ program database 2.00\r\n";
static constexpr size_t pdb2MagicLen = sizeof(pdb2Magic) - 1; // no NUL
static constexpr size_t tpiStreamIndex = 2;
static constexpr size_t pdb2TpiHeaderSize = 0x38;

static Error err(const Twine &msg) {
  return createStringError("VC6 PDB 2.0 type server: " + msg.str());
}

bool isPdb2TypeServer(MemoryBufferRef mb) {
  StringRef buf = mb.getBuffer();
  return buf.size() > pdb2MagicLen &&
         buf.substr(0, pdb2MagicLen) == StringRef(pdb2Magic, pdb2MagicLen);
}

namespace {
struct Pdb2File {
  ArrayRef<uint8_t> data;
  uint32_t pageSize;

  ArrayRef<uint8_t> page(uint32_t p) const {
    uint64_t off = uint64_t(p) * pageSize;
    if (off + pageSize > data.size())
      return {};
    return data.slice(off, pageSize);
  }

  // Concatenate `count` pages starting at `pages[0..count)`, then trim to
  // `byteSize`. Fails loudly (rather than silently dropping the page and
  // shifting every later page's bytes left by one page width) if any page
  // index is out of range -- this is the first parsing surface touching raw
  // untrusted bytes off disk, not output from a trusted compiler run.
  Expected<std::vector<uint8_t>> readStream(ArrayRef<support::ulittle16_t> pages,
                                            uint32_t byteSize) const {
    std::vector<uint8_t> out;
    out.reserve(byteSize);
    for (uint16_t p : pages) {
      ArrayRef<uint8_t> pg = page(p);
      if (pg.empty())
        return err("page index " + Twine(p) + " is out of range");
      out.insert(out.end(), pg.begin(), pg.end());
    }
    if (out.size() > byteSize)
      out.resize(byteSize);
    return out;
  }
};
} // namespace

// Parses the SuperBlock + stream directory and returns the raw bytes of
// stream `tpiStreamIndex` (the TPI stream), still including its own 0x38-byte
// header.
static Expected<std::vector<uint8_t>> readTpiStreamRaw(MemoryBufferRef mb) {
  ArrayRef<uint8_t> data(
      reinterpret_cast<const uint8_t *>(mb.getBufferStart()),
      mb.getBufferSize());
  if (data.size() < 0x40)
    return err("file too short for a SuperBlock");

  uint32_t pageSize = support::endian::read32le(data.data() + 0x2C);
  uint32_t rootSize = support::endian::read32le(data.data() + 0x34);
  if (pageSize == 0 || pageSize > (1u << 20))
    return err("implausible page size " + Twine(pageSize));

  Pdb2File pdb{data, pageSize};

  uint32_t rootPageCount = (rootSize + pageSize - 1) / pageSize;
  if (0x3C + uint64_t(rootPageCount) * 2 > data.size())
    return err("stream directory page list runs off the end of the file");
  ArrayRef<support::ulittle16_t> rootPages(
      reinterpret_cast<const support::ulittle16_t *>(data.data() + 0x3C),
      rootPageCount);

  Expected<std::vector<uint8_t>> rootOrErr = pdb.readStream(rootPages, rootSize);
  if (!rootOrErr)
    return rootOrErr.takeError();
  std::vector<uint8_t> &root = *rootOrErr;
  if (root.size() < 4)
    return err("stream directory too short");

  uint32_t numStreams = support::endian::read32le(root.data());
  // Per-stream: u32 size, u32 reserved.
  if (4 + uint64_t(numStreams) * 8 > root.size())
    return err("stream directory truncated (sizes table)");

  std::vector<uint32_t> sizes(numStreams);
  for (uint32_t i = 0; i < numStreams; ++i)
    sizes[i] = support::endian::read32le(root.data() + 4 + i * 8);

  if (tpiStreamIndex >= numStreams)
    return err("file has no TPI stream (index " + Twine(tpiStreamIndex) +
               " >= " + Twine(numStreams) + " streams)");

  // Page numbers for all streams are concatenated after the sizes table, in
  // stream-index order, skipping any stream whose size is 0.
  size_t p = 4 + size_t(numStreams) * 8;
  ArrayRef<support::ulittle16_t> tpiPages;
  for (uint32_t i = 0; i < numStreams; ++i) {
    uint32_t pages = (sizes[i] + pageSize - 1) / pageSize;
    if (p + pages * 2 > root.size())
      return err("stream directory truncated (page list)");
    if (i == tpiStreamIndex)
      tpiPages = ArrayRef<support::ulittle16_t>(
          reinterpret_cast<const support::ulittle16_t *>(root.data() + p),
          pages);
    p += pages * 2;
  }

  return pdb.readStream(tpiPages, sizes[tpiStreamIndex]);
}

// Converts a record's embedded name from Pascal-style (length-prefixed) to
// null-terminated, in place, given the fixed byte size of whatever
// non-name fields precede it (`prefixSize`, counted from the start of the
// record including its [len][kind] header). Both encodings occupy exactly
// N+1 bytes for an N-character name, so this never changes the record's
// length or shifts any other byte. Returns false (record left untouched) if
// the shape doesn't match what we know how to parse -- callers should treat
// that as "name stays Pascal-encoded", not fatal.
static bool fixupPascalNameDirectAt(MutableArrayRef<uint8_t> rec,
                                    size_t nameOffset) {
  if (nameOffset >= rec.size())
    return false;
  uint8_t nameLen = rec[nameOffset];
  if (nameOffset + 1 + nameLen > rec.size())
    return false; // malformed / not actually a Pascal name here
  // Shift the N name chars left by one (over the length byte), then null-
  // terminate in what used to be the last name byte's slot.
  uint8_t *name = rec.data() + nameOffset;
  for (uint8_t i = 0; i < nameLen; ++i)
    name[i] = name[i + 1];
  name[nameLen] = 0;
  return true;
}

// CodeView numeric-leaf encoding: values < LF_NUMERIC (0x8000) are a plain
// u16; values >= 0x8000 are a 2-byte discriminator tag followed by the value
// itself. Mirrors llvm::codeview::consume(BinaryStreamReader&, APSInt&) in
// RecordSerialization.cpp -- which is itself the authority here, since it's
// the same fixed set that consumer accepts (member offsets / enum values /
// array sizes are always integral, so LF_REAL*/LF_COMPLEX* etc never appear
// in this position and neither llvm nor this reader need to handle them).
// Returns false (uncommon/unsupported encoding) if `firstWord` isn't one of
// these tags and isn't a plain u16.
static bool numericLeafSize(uint16_t firstWord, size_t &size) {
  if (firstWord < LF_NUMERIC) {
    size = 2; // plain u16 numeric leaf
    return true;
  }
  switch (firstWord) {
  case LF_CHAR: // u16 discriminator + i8
    size = 3;
    return true;
  case LF_SHORT:  // u16 discriminator + i16
  case LF_USHORT: // u16 discriminator + u16
    size = 4;
    return true;
  case LF_LONG:  // u16 discriminator + i32
  case LF_ULONG: // u16 discriminator + u32
    size = 6;
    return true;
  case LF_REAL32: // u16 discriminator + 4-byte float
    size = 6;
    return true;
  case LF_REAL64: // u16 discriminator + 8-byte double
    size = 10;
    return true;
  case LF_REAL80: // u16 discriminator + 10-byte extended
    size = 12;
    return true;
  case LF_REAL128: // u16 discriminator + 16-byte float128
    size = 18;
    return true;
  case LF_QUADWORD:  // u16 discriminator + i64
  case LF_UQUADWORD: // u16 discriminator + u64
    size = 10;
    return true;
  default:
    return false; // uncommon numeric-leaf encoding; leave name as-is
  }
}

// As above, but `prefixSize` is followed by a CodeView numeric-leaf-encoded
// value (e.g. a member offset or enum value) before the Pascal name, whose
// own byte width must be determined first.
static bool fixupPascalNameAt(MutableArrayRef<uint8_t> rec,
                              size_t prefixSize) {
  if (rec.size() < prefixSize + 3)
    return false;
  size_t p = prefixSize;
  uint16_t firstWord = support::endian::read16le(rec.data() + p);
  size_t numericFieldSize;
  if (!numericLeafSize(firstWord, numericFieldSize))
    return false;
  p += numericFieldSize;
  return fixupPascalNameDirectAt(rec, p);
}

// LF_MEMBER: [len:2][kind:2][attr:2][type:4][offset-numeric-leaf][name]...
static bool fixupMemberName(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameAt(rec, /*len+kind+attr+type=*/4 + 2 + 4);
}

// LF_FIELDLIST member sub-records have no [len:2] of their own (unlike
// top-level records): they're packed back-to-back as [kind:2][...], each
// individually padded up to a multiple of 4 with an LF_PAD1..3 filler byte,
// and the whole sequence's extent is implied by the *outer* FIELDLIST
// record's declared length. See fixupFieldListMembers, which computes each
// member's numeric-field offset (shape-dependent -- e.g. 8 for LF_MEMBER's
// [kind:2][attr:2][type:4], 4 for LF_ENUMERATE's [kind:2][attrs:2]) and
// calls fixupPascalNameAt directly rather than going through a per-kind
// wrapper like the top-level fixups below.

// LF_STRUCTURE/LF_CLASS (identical shape up to the name; verified against
// llvm's TypeRecordMapping::visitKnownRecord(ClassRecord&) in
// TypeRecordMapping.cpp, which is the ground truth for what the ghash-based
// hashTypeRecord()/TypeDeserializer path expects on read):
// [len:2][kind:2][count:2][properties:2][fieldlist:4][derived:4][vshape:4]
// [size-numeric-leaf][name]...
static bool fixupStructureLikeName(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameAt(rec, /*len+kind+count+props+3 TypeIndices=*/
                           4 + 2 + 2 + 4 + 4 + 4);
}

// LF_UNION: unlike LF_STRUCTURE/LF_CLASS, has no DerivedFrom or VShape
// TypeIndex field (TypeRecordMapping::visitKnownRecord(UnionRecord&):
// MemberCount, Options, FieldList, SizeOf, Name -- no DerivationList/
// VTableShape). Do not merge this with fixupStructureLikeName; the prefix
// is 8 bytes shorter.
// [len:2][kind:2][count:2][properties:2][fieldlist:4][size-numeric-leaf][name]...
static bool fixupUnionName(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameAt(rec, /*len+kind+count+props+fieldlist=*/
                           4 + 2 + 2 + 4);
}

// LF_ARRAY: [len:2][kind:2][elementType:4][indexType:4][size-numeric-leaf]
// [name]... Usually anonymous (empty Pascal name: a 0x00 length byte) since
// arrays are typically embedded as another record's type field rather than
// named in their own right, but the shape (and thus the fixup) is the same
// either way.
static bool fixupArrayLikeName(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameAt(rec, /*len+kind+elementType+indexType=*/
                           4 + 4 + 4);
}

// LF_ENUM: [len:2][kind:2][count:2][properties:2][underlyingType:4]
// [fieldlist:4][name]... Per TypeRecordMapping::visitKnownRecord(EnumRecord&):
// MemberCount, Options, UnderlyingType, FieldList, then straight into the
// name -- unlike LF_STRUCTURE/CLASS/UNION/LF_ARRAY, there is no SizeOf/
// encoded-integer field (an enum's size is implicit from UnderlyingType), so
// the name is NOT preceded by a numeric leaf. Use fixupPascalNameDirectAt
// here, not fixupPascalNameAt.
static bool fixupEnumName(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(
      rec, /*len+kind+count+props+underlying+fieldlist=*/
      4 + 2 + 2 + 4 + 4);
}

// LF_ENUMERATE_ST only ever appears as a nested field-list member (see
// fixupFieldListMembers, which handles it directly via fixupPascalNameAt
// with the nested prefix size); this top-level-shaped wrapper exists only so
// stFixupFor's entry for it has a valid, safe fixName, in case it were ever
// (incorrectly) encountered as a top-level record's own kind.
static bool fixupEnumeratorNameTopLevel(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameAt(rec, /*len+kind+attrs=*/4 + 2);
}

// The following three are, like LF_MEMBER/LF_ENUMERATE, nested-only (no
// top-level form): fixupFieldListMembers dispatches them directly via
// fixupPascalNameDirectAt (no numeric-leaf value field precedes their name,
// unlike LF_MEMBER/LF_ENUMERATE), so these top-level-shaped wrappers exist
// only for a valid, safe stFixupFor::fixName entry.
//
// LF_STMEMBER: [kind:2][attrs:2][type:4][name]... (static data member: a
// plain TypeIndex, no offset -- statics don't live at a fixed in-object
// offset).
static bool fixupStaticMemberNameTopLevel(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(rec, /*len+kind+attrs+type=*/4 + 2 + 4);
}

// LF_METHOD (overload set): [kind:2][count:2][methodList:4][name]...
static bool fixupMethodNameTopLevel(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(rec, /*len+kind+count+methodList=*/4 + 2 + 4);
}

// LF_NESTTYPE: [kind:2][padding:2][type:4][name]...
static bool fixupNestedTypeNameTopLevel(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(rec, /*len+kind+padding+type=*/4 + 2 + 4);
}

// LF_ONEMETHOD: [kind:2][attrs:2][type:4][vftableOffset:4 -- ONLY present if
// attrs' MethodKind sub-field says this method introduces a virtual
// function][name]... The MethodKind occupies bits 2-4 of attrs
// (MethodOptions::MethodKindMask, shifted right by 2); MethodKind::
// IntroducingVirtual or MethodKind::PureIntroducingVirtual means the 4-byte
// VFTableOffset field is present, any other kind means it's omitted -- see
// MemberAttributes::getMethodKind() / OneMethodRecord::isIntroducingVirtual()
// in TypeRecord.h. Unlike the other nested kinds, this one has a genuinely
// conditional prefix length, so it isn't expressible as a single fixed
// offset -- computed directly rather than via nestedShapeFor/NestedShape.
static bool isIntroducingVirtualMethodKind(uint16_t attrs) {
  auto methodKind = MethodKind(
      (attrs & uint16_t(MethodOptions::MethodKindMask)) >> 2);
  return methodKind == MethodKind::IntroducingVirtual ||
         methodKind == MethodKind::PureIntroducingVirtual;
}
static size_t oneMethodPrefixSize(uint16_t attrs, size_t base) {
  return base + (isIntroducingVirtualMethodKind(attrs) ? 4 : 0);
}
// Top-level-shaped wrapper for stFixupFor::fixName (see comment on the
// STMEMBER/METHOD/NESTTYPE wrappers above); LF_ONEMETHOD_ST normally only
// appears nested, handled directly in fixupFieldListMembers.
static bool fixupOneMethodNameTopLevel(MutableArrayRef<uint8_t> rec) {
  if (rec.size() < 6)
    return false;
  uint16_t attrs = support::endian::read16le(rec.data() + 4); // len+kind+attrs
  return fixupPascalNameDirectAt(rec, oneMethodPrefixSize(attrs, 4 + 2 + 4));
}

// Three more nested-only field-list member kinds, assumed to share the same
// [kind:2][word:2][type:4][name]... shape as LF_STMEMBER/LF_METHOD/LF_NESTTYPE
// above (no numeric leaf): friend-function declarations, "extended"
// nested-type declarations (adds access attrs where LF_NESTTYPE has only
// padding), and member-modify records (multiple-inheritance override
// bookkeeping). None of these three have a TYPE_RECORD/MEMBER_RECORD entry
// in CodeViewTypes.def, so unlike LF_STMEMBER/LF_METHOD/LF_NESTTYPE/
// LF_ONEMETHOD there's no TypeRecordMapping.cpp shape to verify against --
// this is cvinfo.h-by-analogy, unverified (same caveat as fixupAliasName
// below). Same top-level-shaped-wrapper caveat as the others -- real
// occurrences are nested, handled via nestedShapeFor/fixupFieldListMembers.
static bool fixupFriendFcnNameTopLevel(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(rec, /*len+kind+pad+type=*/4 + 2 + 4);
}
static bool fixupNestTypeExNameTopLevel(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(rec, /*len+kind+attrs+type=*/4 + 2 + 4);
}
static bool fixupMemberModifyNameTopLevel(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(rec, /*len+kind+pad+type=*/4 + 2 + 4);
}

// LF_ALIAS (typedef): [len:2][kind:2][utype:4][name]... -- genuinely
// top-level only (a typedef isn't a field-list member). No modern
// TypeRecord/deserializer class exists for this in llvm (only the raw
// CV_TYPE kind enum value), so downstream consumers see it as an opaque
// record; that's fine, all we need is a well-formed length/kind/name.
static bool fixupAliasName(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(rec, /*len+kind+utype=*/4 + 4);
}

// LF_DEFARG (default argument expression, e.g. `void F(int x = 5)`):
// [len:2][kind:2][type:4][expr]... `expr` is Pascal/null-terminated source
// text (not a symbol name), but the fixup is byte-identical. Top-level only
// (referenced by an LF_ARGLIST/method's argument list, not a field member).
// Like LF_ALIAS below, LF_DEFARG has no TYPE_RECORD entry in
// CodeViewTypes.def and thus no TypeRecordMapping.cpp shape to check
// against -- this is old cvinfo.h-by-memory reasoning, unverified against
// llvm ground truth.
static bool fixupDefArgName(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(rec, /*len+kind+type=*/4 + 4);
}

// LF_DIMARRAY (multi-dimensional array, rare -- Fortran-oriented, unlikely
// in VC6 C/C++ but cheap to support): [len:2][kind:2][elementType:4]
// [dimInfo:4][name]... Top-level only. Also no TypeRecordMapping.cpp entry
// to check against -- same unverified-against-llvm-ground-truth caveat as
// LF_ALIAS/LF_DEFARG.
static bool fixupDimArrayName(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(rec, /*len+kind+elementType+dimInfo=*/
                                 4 + 4 + 4);
}

// LF_PRECOMP (precompiled-header type-range reference): [len:2][kind:2]
// [start:4][count:4][signature:4][name]... Matches llvm's PrecompRecord
// (StartTypeIndex/TypesCount/Signature/PrecompFilePath). Top-level only.
// May be unused if bw1-decomp's objects don't use /Yc /Yu PCH, but handled
// for completeness rather than left as a silent gap.
static bool fixupPrecompName(MutableArrayRef<uint8_t> rec) {
  return fixupPascalNameDirectAt(rec, /*len+kind+start+count+signature=*/
                                 4 + 4 + 4 + 4);
}

// Old "_ST" (Pascal-name) leaf kinds whose non-name field layout is
// otherwise identical to a validated modern counterpart: the modern kind
// they should be rewritten to (so the rest of LLVM's CodeView tooling
// recognizes them), paired with the name-fixup shape to apply.
struct StStructureFixup {
  TypeLeafKind modernKind;
  bool (*fixName)(MutableArrayRef<uint8_t>);
};
static std::optional<StStructureFixup> stFixupFor(uint16_t leaf) {
  switch (leaf) {
  case LF_STRUCTURE_ST:
    return StStructureFixup{LF_STRUCTURE, fixupStructureLikeName};
  case LF_CLASS_ST:
    return StStructureFixup{LF_CLASS, fixupStructureLikeName};
  case LF_UNION_ST:
    return StStructureFixup{LF_UNION, fixupUnionName};
  case LF_MEMBER_ST:
    return StStructureFixup{LF_MEMBER, fixupMemberName};
  case LF_ARRAY_ST:
    return StStructureFixup{LF_ARRAY, fixupArrayLikeName};
  case LF_ENUM_ST:
    return StStructureFixup{LF_ENUM, fixupEnumName};
  case LF_ENUMERATE_ST: // normally only nested; see fixName comment
    return StStructureFixup{LF_ENUMERATE, fixupEnumeratorNameTopLevel};
  case LF_STMEMBER_ST: // normally only nested; see fixName comment
    return StStructureFixup{LF_STMEMBER, fixupStaticMemberNameTopLevel};
  case LF_METHOD_ST: // normally only nested; see fixName comment
    return StStructureFixup{LF_METHOD, fixupMethodNameTopLevel};
  case LF_NESTTYPE_ST: // normally only nested; see fixName comment
    return StStructureFixup{LF_NESTTYPE, fixupNestedTypeNameTopLevel};
  case LF_ONEMETHOD_ST: // normally only nested; see fixName comment
    return StStructureFixup{LF_ONEMETHOD, fixupOneMethodNameTopLevel};
  case LF_FRIENDFCN_ST: // normally only nested; see fixName comment
    return StStructureFixup{LF_FRIENDFCN, fixupFriendFcnNameTopLevel};
  case LF_NESTTYPEEX_ST: // normally only nested; see fixName comment
    return StStructureFixup{LF_NESTTYPEEX, fixupNestTypeExNameTopLevel};
  case LF_MEMBERMODIFY_ST: // normally only nested; see fixName comment
    return StStructureFixup{LF_MEMBERMODIFY, fixupMemberModifyNameTopLevel};
  case LF_ALIAS_ST: // typedef; top-level only
    return StStructureFixup{LF_ALIAS, fixupAliasName};
  case LF_DEFARG_ST: // default argument expression; top-level only
    return StStructureFixup{LF_DEFARG, fixupDefArgName};
  case LF_DIMARRAY_ST: // top-level only
    return StStructureFixup{LF_DIMARRAY, fixupDimArrayName};
  case LF_PRECOMP_ST: // top-level only
    return StStructureFixup{LF_PRECOMP, fixupPrecompName};
  // LF_MANAGED_ST: .NET/managed-code metadata reference. Never emitted by
  // VC6 compiling native C/C++ (no /clr in this era), so deliberately left
  // unhandled rather than guessed at -- not a gap for this project's actual
  // inputs.
  default:
    return std::nullopt;
  }
}

// Walks a decoded LF_FIELDLIST's content (immediately after its [len][kind]
// header) member-by-member -- mirroring llvm's own handleFieldList()
// size/padding logic -- and rewrites each recognized "_ST" member's kind to
// modern in place, fixing up its Pascal name in the same pass, so the rest
// of LLVM's CodeView tooling recognizes it. Stops (leaving the remainder
// untouched) at the first member kind we don't know the shape of.

// Describes where a nested member's name-area begins (byte offset from the
// member's own [kind:2]) and whether a CodeView numeric-leaf-encoded value
// (whose own byte width must be resolved first) precedes the Pascal name
// there, for each nested member kind this function knows how to size.
struct NestedShape {
  size_t prefixSize;
  bool hasNumericLeaf;
};
static std::optional<NestedShape> nestedShapeFor(TypeLeafKind modernKind) {
  switch (modernKind) {
  case LF_MEMBER:
    return NestedShape{8, true}; // [kind:2][attrs:2][type:4] + numeric-leaf
  case LF_ENUMERATE:
    return NestedShape{4, true}; // [kind:2][attrs:2] + numeric-leaf
  case LF_STMEMBER:
    return NestedShape{8, false}; // [kind:2][attrs:2][type:4], no leaf
  case LF_METHOD:
    return NestedShape{8, false}; // [kind:2][count:2][methodList:4], no leaf
  case LF_NESTTYPE:
    return NestedShape{8, false}; // [kind:2][padding:2][type:4], no leaf
  case LF_FRIENDFCN:
    return NestedShape{8, false}; // [kind:2][padding:2][type:4], no leaf
  case LF_NESTTYPEEX:
    return NestedShape{8, false}; // [kind:2][attrs:2][type:4], no leaf
  case LF_MEMBERMODIFY:
    return NestedShape{8, false}; // [kind:2][padding:2][type:4], no leaf
  default:
    return std::nullopt;
  }
}

// LF_BCLASS/LF_VBCLASS/LF_IVBCLASS/LF_VFUNCTAB/LF_INDEX have no embedded
// name in EITHER old or new CodeView, so there's no "_ST" sibling for them
// (they don't appear in stFixupFor) and no Pascal-name fixup is needed --
// they're already byte-identical to their modern form. But the field-list
// walker still needs their size to skip over them and keep going, mirroring
// llvm's own handleBaseClass/handleVirtualBaseClass/handleVFPtr/
// handleListContinuation in TypeIndexDiscovery.cpp. Without this, the walker
// would treat any class with a base class (i.e. almost any class using
// inheritance), a virtual base, or a vtable pointer as "unknown member kind"
// and bail immediately, leaving the rest of the field list un-fixed-up --
// this was the actual cause of real corruption downstream (a Pascal-encoded
// name misread as null-terminated by later tooling), not any of the "_ST"
// leaf kinds.
static std::optional<size_t> fixedFieldListMemberSize(uint16_t kind,
                                                       ArrayRef<uint8_t> data) {
  switch (TypeLeafKind(kind)) {
  case LF_BCLASS:
    // [kind:2][attrs:2][type:4][offset-numeric-leaf]
    if (data.size() < 10)
      return std::nullopt;
    {
      size_t n;
      if (!numericLeafSize(support::endian::read16le(data.data() + 8), n))
        return std::nullopt;
      return 8 + n;
    }
  case LF_VBCLASS:
  case LF_IVBCLASS: {
    // [kind:2][attrs:2][baseType:4][vbptrType:4][vbpOffset-leaf][vbOffset-leaf]
    if (data.size() < 14)
      return std::nullopt;
    size_t n1;
    if (!numericLeafSize(support::endian::read16le(data.data() + 12), n1))
      return std::nullopt;
    size_t after1 = 12 + n1;
    if (data.size() < after1 + 2)
      return std::nullopt;
    size_t n2;
    if (!numericLeafSize(support::endian::read16le(data.data() + after1), n2))
      return std::nullopt;
    return after1 + n2;
  }
  case LF_VFUNCTAB:
    // [kind:2][padding:2][type:4]
    return data.size() >= 8 ? std::optional<size_t>(8) : std::nullopt;
  case LF_INDEX:
    // [kind:2][padding:2][type:4] (points at a continuation LF_FIELDLIST)
    return data.size() >= 8 ? std::optional<size_t>(8) : std::nullopt;
  default:
    return std::nullopt;
  }
}

// Note: hitting one unrecognized member kind stops conversion for every
// member *after* it too, not just that one -- a single unexpected kind
// partway through a class definition leaves the remaining, otherwise
// convertible members still Pascal-encoded. Not corruption (consistent with
// this project's "leave broken, don't fake it" philosophy), but the blast
// radius is bigger than "one member" if it ever happens.
static void fixupFieldListMembers(MutableArrayRef<uint8_t> content) {
  size_t p = 0;
  while (p + 2 <= content.size()) {
    uint16_t kind = support::endian::read16le(content.data() + p);

    if (std::optional<size_t> size =
            fixedFieldListMemberSize(kind, content.slice(p))) {
      p += *size;
      if (p < content.size() && content[p] >= LF_PAD0)
        p += content[p] & 0x0F;
      continue;
    }

    std::optional<StStructureFixup> fx = stFixupFor(kind);
    if (!fx)
      return; // unknown/unhandled nested member kind; stop here

    // LF_ONEMETHOD has a genuinely conditional prefix length (see
    // oneMethodPrefixSize), not expressible via the fixed-offset NestedShape
    // table below, so it's handled as its own case.
    if (fx->modernKind == LF_ONEMETHOD) {
      if (p + 8 > content.size())
        return;
      uint16_t attrs = support::endian::read16le(content.data() + p + 2);
      // [kind:2][attrs:2][type:4] = 8-byte fixed prefix, then optionally a
      // 4-byte VFTableOffset, then the name -- see oneMethodPrefixSize.
      size_t nameOff = oneMethodPrefixSize(attrs, p + 8);
      if (nameOff >= content.size())
        return;
      uint8_t nameLen = content[nameOff];
      if (nameOff + 1 + nameLen > content.size())
        return;
      size_t memberLen = (nameOff + 1 + nameLen) - p;

      support::endian::write16le(content.data() + p, uint16_t(fx->modernKind));
      fixupPascalNameDirectAt(content.slice(p, memberLen),
                              nameOff - p);

      p += memberLen;
      if (p < content.size() && content[p] >= LF_PAD0)
        p += content[p] & 0x0F;
      continue;
    }

    std::optional<NestedShape> shape = nestedShapeFor(fx->modernKind);
    if (!shape)
      return; // unknown/unhandled nested member shape; stop here

    size_t q = p + shape->prefixSize;
    if (shape->hasNumericLeaf) {
      // Recompute this member's length the same way handleDataMember() /
      // handleEnumerator() do: prefix + encoded-integer + C-string name.
      if (q + 2 > content.size())
        return;
      uint16_t firstWord = support::endian::read16le(content.data() + q);
      size_t numericFieldSize;
      if (!numericLeafSize(firstWord, numericFieldSize))
        return; // uncommon numeric-leaf encoding; stop here
      q += numericFieldSize;
    }
    if (q >= content.size())
      return;
    uint8_t nameLen = content[q];
    if (q + 1 + nameLen > content.size())
      return;
    size_t memberLen = (q + 1 + nameLen) - p;

    support::endian::write16le(content.data() + p, uint16_t(fx->modernKind));
    if (shape->hasNumericLeaf)
      fixupPascalNameAt(content.slice(p, memberLen), shape->prefixSize);
    else
      fixupPascalNameDirectAt(content.slice(p, memberLen), shape->prefixSize);

    p += memberLen;
    if (p < content.size() && content[p] >= LF_PAD0)
      p += content[p] & 0x0F; // skip LF_PAD1..3 filler, same as handleFieldList
  }
}

Expected<ArrayRef<uint8_t>> readPdb2TypeServerTypes(MemoryBufferRef mb,
                                                    BumpPtrAllocator &alloc) {
  Expected<std::vector<uint8_t>> tpiOrErr = readTpiStreamRaw(mb);
  if (!tpiOrErr)
    return tpiOrErr.takeError();
  std::vector<uint8_t> &tpi = *tpiOrErr;

  if (tpi.empty()) {
    // A genuinely empty TPI stream means this TU defines no local types of
    // its own (observed for real /Zi objects, e.g. one that only uses types
    // already known from elsewhere) -- valid and common, not an error.
    return ArrayRef<uint8_t>();
  }
  if (tpi.size() < pdb2TpiHeaderSize)
    return err("TPI stream shorter than its own header");

  uint32_t typeIndexBegin = support::endian::read32le(tpi.data() + 4);
  uint32_t typeIndexEnd = support::endian::read32le(tpi.data() + 8);
  uint32_t typeRecordBytes = support::endian::read32le(tpi.data() + 16);
  if (typeIndexBegin == 0 || typeIndexBegin > TypeIndex::FirstNonSimpleIndex)
    return err("implausible TypeIndexBegin " + Twine(typeIndexBegin));
  if (typeIndexEnd < typeIndexBegin)
    return err("TypeIndexEnd " + Twine(typeIndexEnd) +
               " precedes TypeIndexBegin " + Twine(typeIndexBegin));
  if (pdb2TpiHeaderSize + uint64_t(typeRecordBytes) > tpi.size())
    return err("type record area runs past the end of the TPI stream");

  // Copy just the record bytes out into an LLD-owned, mutable buffer -- this
  // becomes the object's new `debugTypes`.
  uint8_t *buf = alloc.Allocate<uint8_t>(typeRecordBytes);
  memcpy(buf, tpi.data() + pdb2TpiHeaderSize, typeRecordBytes);
  MutableArrayRef<uint8_t> out(buf, typeRecordBytes);

  // Embedded TypeIndex references inside this stream's records are already
  // encoded exactly the way a modern object's local .debug$T would encode
  // them: `0x1000 + N` where N is the 0-based sequential position of the
  // referenced record within this same stream -- e.g. record position 1's
  // LF_POINTER has `referent = 0x1000` (position 0); position 3's LF_POINTER
  // has `referent = 0x1002` (position 2); matching what
  // TypeIndex::toArrayIndex() (`value - 0x1000`) expects. No rewriting of
  // TypeIndex values is needed. typeIndexBegin/typeIndexEnd (see
  // readTpiStreamRaw) are bookkeeping internal to the PDB 2.0 container's
  // own record layout, not a numbering embedded references use. The only
  // transformation needed is rewriting old "_ST" (Pascal-name) leaf kinds to
  // their modern equivalents.
  size_t pos = 0;
  while (pos < out.size()) {
    if (pos + sizeof(RecordPrefix) > out.size())
      return err("type record truncated at offset " + Twine(pos));
    uint16_t length = support::endian::read16le(out.data() + pos);
    if (pos + 2 + length > out.size())
      return err("type record overruns stream at offset " + Twine(pos));
    MutableArrayRef<uint8_t> rec = out.slice(pos, 2 + length);

    // Old "_ST" (Pascal-name) records must be rewritten to their modern
    // kind so the rest of LLVM's CodeView tooling recognizes them. Only
    // commit the kind rewrite if the name fixup actually succeeds -- fixName
    // can fail if this record's shape doesn't match what we assumed (e.g. an
    // untested/speculative kind with a wrong byte-offset guess); if we wrote
    // the modern kind regardless, the record would end up with a modern tag
    // but a still-Pascal-encoded name, which is silently self-inconsistent
    // rather than caught (the same corruption class the LF_UNION_ST and
    // LF_ENUM_ST bugs produced, just with no code path left to notice it).
    std::optional<StStructureFixup> stFixup =
        stFixupFor(support::endian::read16le(rec.data() + 2));
    if (stFixup && stFixup->fixName(rec))
      support::endian::write16le(rec.data() + 2, uint16_t(stFixup->modernKind));
    if (CVType(rec).kind() == LF_FIELDLIST)
      fixupFieldListMembers(rec.drop_front(sizeof(RecordPrefix)));

    pos += 2 + length;
  }

  return ArrayRef<uint8_t>(out);
}

} // namespace lld::coff
