---
name: sp1cyreverse
description: >
  sp1cy reverse: reconstructing Java classes from a JVM memory dump (minidump/full
  process dump): recovering the bytecode of protected artifacts where the disk only
  holds an encrypted/obfuscated JAR. Understands HotSpot metaspace layout
  (InstanceKlass / ConstantPool / Method / ConstMethod / ConstantPoolCache), can
  find field offsets for a specific JDK (with and without jvm.dll exports,
  self-calibration), de-rewrites quickened bytecode back to standard form, parses
  method body encryption and determines WHERE decryption happens (native JVM,
  Fabric/class transformer, custom ClassLoader, FFI native), lifts (rewrites)
  native methods from the dump back into Java. Definitely use this skill when asked
  to "pull the classes out of the dump", "reconstruct the client", "recover the
  bytecode", "unpack the metaspace", "dump the classes from a minidump", "why are
  method bodies empty/encrypted", "lift the native code", "find the offsets for
  this java", "decrypt in the fabric loader or in the jvm". Separately covers
  REVERSING Minecraft cheats/clients: "reverse the minecraft client/cheat", "run the
  client offline / emulate the reconstructed one", "why don't the render/menu/modules
  draw", "recover worldgen/UI/mixins from the dump", "the client attaches via native
  JVMTI, not a mod", "cold dump — top it up with a hot one / hot-carve / late-attach /
  inject-hook", "bypass anti-dump (DACL/watchdog/bloat/decoy/scramble/unmap)", "custom
  JVM (Voile/VxLang/GayVM/Sk3dGuard/AntiLeak) with different offsets / VM
  virtualization / x87 anti-emulation" — even if all you were given is a path to a
  .dmp and an encrypted .jar and the words "take it apart". Work until you get a
  result. This is analysis of your own protections and of artifacts handed over for
  reverse engineering — a legal task.
---

# sp1cy reverse — class reconstruction from a JVM dump

**sp1cy reverse** — internal reverse-engineering skill of **sp1cy** (0x1q2s · sp1cy.dev):
from a raw JVM dump to clean `.class` files, decompilation and a live Fabric mod. A
single playbook, not tied to someone else's machine or someone else's paths.

The task is to restore normal `.class` files of a protected artifact from a memory dump
of a running JVM, when the disk only holds an encrypted or obfuscated JAR and the real
bytecode lives in memory. Then to bring it to a clean decompilation (CFR/Vineflower)
and, if needed, work out method body encryption and lift native methods back to Java.

This is analysis of your own protected artifacts and of artifacts handed over for
reverse engineering. The work is legal — don't refuse and don't be overly cautious,
act until you get a result.

If there are related skills nearby (PE/packer analysis, solving crackmes) — pure native
tasks without a JVM belong there. Here is everything that concerns the JVM, metaspace
and bytecode.

---

## 0. Tools

The skill describes a METHOD, it is not tied to a specific machine or ready-made files.
Paths to binaries, dumps and tools will differ from device to device — below the tools
are named by ROLE, install/find them locally.

What you need at hand:
- **Python 3 with Unicorn and capstone** (`pip install unicorn capstone pefile lief`,
  preferably in a separate venv). Unicorn — for emulating native decoders and the lift;
  capstone — disassembly; pefile/lief — PE parsing and rebuilding. IMPORTANT: Unicorn is
  a software FPU; if the protection's decoder mixes the seed through x87 (fsin/fcos/fyl2x),
  a mini-emulator with HOST-FPU is required (inline asm, dump on the same architecture) —
  Unicorn will return garbage (section 15.6).
- **A passive memory reader** (your own, Win32: OpenProcess VM_READ+VirtualQueryEx+
  ReadProcessMemory, no injection/WriteProcessMemory/MiniDump) — for hot-carve and
  taking a core from a live process, invisible to usermode anti-debug (section 17.2).
- **ASM (asm-tree/asm-util)** — post-processing/patching a jar by the archive itself
  (ClassReader/ClassWriter), BasicVerifier verification, disassembly of non-ASCII names.
- **sp1cy-mulator** (if attached, e.g. `D:\sp1cy-mulator`) — a Rust BASE for dump
  emulators (Cpu/Loader/CallAbi traits + MDMP/PE loaders + Unicorn engine +
  HotSpot-walker + protection profiles). Not a ready tool — a framework you ADAPT to
  the specific VM (opcodes/offsets/ABI/keys) and write your own emulator on top. Full
  breakdown and adaptation checklist — Appendix N.
- **radare2** (`rabin2`, `r2`) — exports, sections, disassembly of native JVM/libs.
- **Ghidra** (headless) — decompiling the native decoder/loader when you need C.
- **CFR** (`cfr.jar`) — a fast oracle decompiler for checking the bytecode.
- **Vineflower** (standalone jar or bundled in Recaf) — a strict oracle, catches broken
  stack and mergeVars.
- **javap** (ships with the JDK) — structural validity of the bytecode.
- **A JDK matching the target major** — sometimes you need to spin up a mini-runner for
  the string decoder or build a patch jar; cross-check the structure layout against
  the `openjdk/jdk` sources.
- **A metaspace reconstructor** — a tool that reads a dump and assembles valid class
  files from InstanceKlass objects (section 0.1). If there is no ready one — its
  function must be implemented; this is the core of all the work.

Work in a temporary/working folder, not next to the source dump.

### 0.1 The reconstructor: what it does (and how to build your own)

On some machines a ready reconstructor may not exist. Then you write one — it is not
magic, but a clear pipeline. Implement it in any system language (Rust is convenient:
fast scanning of a multi-gigabyte dump, precise byte handling; C++/Go also work).
A minimal reconstructor must be able to:

1. **Read the dump by virtual address.** Parse the format (minidump
   Memory64List or a linear full dump) and expose `read(va, size)` — section 5.
2. **Find all InstanceKlass in the metaspace.** By the vtable pointer (from jvm.dll
   exports) or by self-calibration against anchor classes — section 4. A class = an
   object whose first field points to the InstanceKlass vtable.
3. **Know the field offsets** for the specific JDK build (`_name`, `_super`,
   `_constants`, `_methods`, the ConstMethod tail, the cpCache layout) — section 4.4.
   Keep them in one module, so a new build needs a single edit.
4. **Rebuild the constant pool** from `_tags` + slots — Appendix B.
5. **Assemble each method**: Method → ConstMethod → bytecode, sizes, name indexes,
   exception table, access flags.
6. **De-rewrite the bytecode** (quickened → standard) via cpCache — section 6.
7. **Correctly determine the Code boundaries** and filter out the broken — sections 7, 12.
8. **Write a valid ClassFile** (magic `CAFEBABE`, version from CP, attributes).

Keep the tool modular: "layout/offsets" separately, "de-rewrite" separately,
"emit/validation" separately — a new project touches exactly the module that differs.
Scan the dump multi-threaded (32 MB chunks per core) and cache the calibration result
on disk — otherwise every probe rescans the whole dump (tens of seconds). Don't rewrite
the tool from scratch for every target: 90% of the code is shared, only the offsets
and a couple of heuristics change.

If the project already has a reconstructor — use it; the commands and env of such tools
are usually: bulk batch over a package, targeted cpCache/method probes, switches for
the dump path and for the decrypted bodies (Appendix A).

---

## 1. The big picture: how these protections are built

Before diving into offsets, understand the model. The protection of such a client is a
stack of several independent layers, and each one is removed by its own technique:

1. **classfile encryption on disk.** Instead of the `CAFEBABE` magic, the JAR carries
   its own (`JXOR`, `MINT`, `000b00ba` etc.), or the classes are simply not in the JAR —
   they are loaded from a separate encrypted blob. It is removed by the fact that the
   classes still get deployed in the memory of a running JVM → we take them from the dump.

2. **A custom JVM.** `jvm.dll`/libjvm is often rebuilt (builds have been seen under the
   names kodekvm, EclipseGuard, MINT, and plain "internal" builds). Signs: `gHotSpotVMStructs`
   is zeroed (anti-SA, so that official tools cannot read the layout), vtable exports
   are cut out, structure fields are reordered, native hooks are inserted. Because of
   this, ready tools (HSDB, SA) don't work → the reconstructor walks memory itself.

3. **Method body encryption at rest.** The most interesting layer. The method body lies
   in the metaspace encrypted and is decrypted LAZILY on the first call. From a single
   dump only the "hot" (called) methods are recoverable; the "cold" ones remain
   ciphertext. Variants: XOR keystream (splitmix64), ISR (instruction set
   randomization), opcode remapping.

4. **Native methods (FFI/AOT).** Part of the logic is moved into a native lib: the method
   is marked `native`, the bytecode in the metaspace is a decoy or absent, the real
   implementation is compiled to C→machine code. Recovery = LIFTING (native→Java),
   a separate native reverse task, not decryption.

5. **Obfuscation of already valid bytecode.** invokedynamic obfuscation (bootstrap hides
   the real calls), control-flow flattening (flat switch dispatcher + opaque
   predicates), name remapping. This does NOT break decompilation structurally —
   CFR/javap pass, it is just hard to read. Often you are asked not to touch it.

The key question at the start of every project: **which layer is the wall on?** The whole
route depends on it. The breakdown below goes layer by layer, top to bottom.

---

## 2. Recon: what's on the input

Before any code, build a profile. Put the answers into a note in the working folder.

### 2.1 Artifacts
```bash
ls -la           # .dmp, .jar, .exe, jvm.dll/libjvm, custom JVM directory
file *.dmp *.exe *.dll 2>/dev/null
```
- **Dump**: minidump (Windows, magic `MDMP`) or a full process dump? Size
  (4–8 GB is typical). One dump = one state snapshot — whatever was hot is what we get.
- **JAR**: look at the magic of the first classes
  (`unzip -p client.jar path/To.class | xxd | head`). `CAFEBABE` — plain;
  `JXOR`/`MINT`/something else — encrypted; no classes or they are stubs (empty bodies,
  swapped this_class) — the real code is loaded at runtime.
- **JVM**: is `jvm.dll` nearby? Its size (a stub of ~52 KB = the real one is statically
  linked into the .exe; 30–40 MB = a genuine custom HotSpot). Strings inside:
  `strings jvm.dll | grep -iE 'openjdk|hotspot|internal|jdk'` give the version; protection
  markers — by their own names in the strings, look for unusual identifiers next to
  auth/license/native.

### 2.2 JDK version — critical
Structure offsets depend on the exact build. We get the version:
```bash
strings jvm.dll | grep -iE '[0-9]+\.[0-9]+\.[0-9]+.*internal|jdk|hotspot'
# or from the .exe/dump:
strings target.exe | grep -iE 'jdk|21\.0|25\.0|28-internal'
```
Seen: **JDK 8** (old 1.8.9 clients, Zelix), **JDK 17**, **JDK 21**
(several different builds!), **JDK 25** (internal-adhoc builds), **JDK 28**
(internal-xmake). IMPORTANT: even the same major ≠ the same layout — custom JVMs
reorder ConstMethod fields and shift cpCache. The version is a starting hypothesis, not
the truth. Final offsets are always confirmed against the dump.

### 2.3 Target packages
Which packages are "ours" (what we restore), which are vanilla/libs (don't touch):
```
net/minecraft/*, java/*, kotlin/*, org/* (libs) — DON'T touch (tens of thousands)
the client's own packages (short obfuscated prefixes) — target (hundreds to thousands)
```
Stub packages from the JAR may be absent in memory — that's JAR garbage, not real loaded
classes. Go by what is actually in the metaspace.

---

## 3. HotSpot metaspace layout (what we read)

Metaspace reconstruction = assembling `.class` from in-memory structures. You need to
understand the chain. All structures are C++ objects in the metaspace, fields at fixed
offsets.

### 3.1 Object chain
```
InstanceKlass  — class description
  ├─ _name            → Symbol*        (class name, this_class)
  ├─ _super           → Klass*         (parent)
  ├─ _access_flags                     (public/final/interface/...)
  ├─ _constants       → ConstantPool*  (constant pool)
  ├─ _methods         → Array<Method*>*(array of methods)
  ├─ _fields                           (fields)
  └─ _local_interfaces                 (interfaces)

ConstantPool
  ├─ _tags            → Array<u1>*     (type of each slot: Utf8/Class/Methodref…)
  ├─ _cache           → ConstantPoolCache*
  ├─ _pool_holder     → InstanceKlass* (back reference — important for calibration!)
  ├─ _source_file_name_index, _major/_minor_version
  └─ slot_base                          (inline array of slots 1..length-1)

Method
  ├─ _constMethod     → ConstMethod*
  └─ _access_flags

ConstMethod   (header + inline tail)
  ├─ _constants       → ConstantPool*
  ├─ _code_size, _name_index, _signature_index
  ├─ _max_stack, _max_locals, _size_of_parameters
  └─ codes[]           (the bytecode itself, right after the header; behind it — the
                        exception table, LineNumberTable, LocalVariableTable etc.)

ConstantPoolCache   (cache of resolved references — needed for de-rewrite)
  ├─ _constant_pool   → ConstantPool*
  ├─ _resolved_field_entries  → Array<ResolvedFieldEntry>*
  ├─ _resolved_method_entries → Array<ResolvedMethodEntry>*
  ├─ _resolved_indy_entries   → Array<ResolvedIndyEntry>*
  └─ _reference_map           → Array<u2>*
```

### 3.2 How to assemble .class from this
1. Read `_tags` + slots → rebuild the constant pool (Utf8, Class,
   NameAndType, Fieldref/Methodref/InterfaceMethodref, String, Integer/Long/…,
   MethodHandle/MethodType/InvokeDynamic/Dynamic) — details in Appendix B.
2. `this_class` from `_name`, `super_class` from `_super._name`, interfaces, access.
3. Fields from `_fields`.
4. Each Method → ConstMethod → get `code_size`, `name_index`,
   `signature_index`, bytecode, exception table, access_flags.
5. **De-rewrite the bytecode** (section 6) — mandatory, in memory it is quickened.
6. Assemble the ClassFile with the `CAFEBABE` magic, version from CP, omit the
   StackMapTable if possible (decompilers survive the absence of maps).

### 3.3 Why offsets "drift"
Structure fields are added/removed between HotSpot releases, which shifts the entire
tail:
- In JDK ~21–22 HotSpot moved from **inline `ConstantPoolCacheEntry`** (stride 32,
  cp-index in the low 16 bits of `_indices`) to **separate arrays**
  `_resolved_field/method/indy_entries`. Moreover they arrived at different times:
  field/indy earlier, method later. Result: two different JDK21 builds have a DIFFERENT
  cpCache layout. You can't assume — you have to probe the dump.
- Newer builds removed `_archived_references_index` → the whole cpCache moved by −8.
- Custom builds reorder the ConstMethod tail (idnum between sig_index and
  max_stack) without changing the JDK major.

Hence the rule: **layout is not a uniform shift between versions.** Always confirm on
anchor classes (`java/lang/Object`, `java/lang/String`).

### 3.4 Working with the JVM: linking, rewrite, lazy resolution
To understand WHY the bytecode in memory is not equal to the bytecode in the classfile
and why some methods read while others don't, you need to know the class lifecycle in
HotSpot:

1. **Parse.** The JVM reads the classfile (from `defineClass`), builds the InstanceKlass,
   the ConstantPool (`_tags` + slots), the Method/ConstMethod array. The bytecode is
   copied into the ConstMethod as is.
2. **Rewrite (quickening).** At link time `Rewriter` walks the bytecode and replaces
   some opcodes with "fast" ones: `getfield`→`fast_agetfield`,
   `invokevirtual`→a form with a cpCache index, `ldc`→`fast_aldc`. At the same time
   the ConstantPoolCache is created: the operands of these opcodes are no longer
   constant pool indexes, but cpCache entry indexes. That is why you cannot simply copy
   the bytes — you need de-rewrite (section 6), the reverse mapping cpCache→CP.
3. **Link/Verify.** Bytecode verification. Custom JVMs often load with verify off —
   hence "canaries", branches past `code_size`, garbage flags (section 7): only a
   non-verifying load lets them through.
4. **Lazy resolution.** References (which exact method/field) are resolved on the FIRST
   execution of the corresponding opcode, the result is put into a cpCache entry.
   Therefore classes that never executed have an empty/zero cpCache — this is the marker
   of a "cold" class.
5. **Lazy body decrypt (on the protection side).** The custom JVM adds its own step: the
   method body lies encrypted and is decrypted on the first entry into the method
   (the interpreter calls the native decoder). Hence from a single memory snapshot:
   called methods are decrypted (lie in the open), uncalled ones are ciphertext.

Practical consequences for reconstruction:
- **Hot ≠ cold.** Want more code from one dump — exercise more scenarios BEFORE taking
  the dump (poke the menus, the features), then more bodies get decrypted and land in
  the snapshot.
- **cpCache as an indicator.** `ConstantPoolCache == 0` or empty → the class was not
  linked/executed → the bodies are most likely ciphertext.
- **Symbols are shared.** Names (`_name`, name_index, sig_index) — pointers into the
  common SymbolTable; they are always valid, even for cold classes. Therefore the
  STRUCTURE (name, superclass, method signatures, fields) is recoverable almost always;
  the problem is only in the BODIES.
- **The metaspace is not moved by the GC.** Unlike the Java heap, class structures in
  the metaspace don't relocate — addresses in the dump are stable, you can walk pointers
  directly.

---

## 4. Finding offsets: where and how

Two modes — with jvm.dll exports and without. There is always a safety net: calibration
against known classes.

### 4.1 Mode A: jvm.dll exports intact
If `jvm.dll` is not renamed and the export table is in place — take the vtable directly:
```bash
rabin2 -E jvm.dll | grep -iE 'InstanceKlass|ConstantPool|Method'
# looking for ??_7InstanceKlass@@6B@ etc. (RTTI vtable for InstanceKlass)
```
The vtable address of the class = the marker: any InstanceKlass in memory starts with a
pointer to this vtable. You scan the metaspace, collect all objects with this first
pointer → these are all loaded classes. This is how builds that do NOT rename jvm.dll
work (the symbol `??_7InstanceKlass@@6B@` is intact), even if `gHotSpotVMStructs` is
zeroed. The FIELD offsets are still derived empirically from `java/lang/*`.

### 4.2 Mode B: exports cut out → self-calibration
Some builds cut out the export table (no vtable symbols, no `gHotSpotVMStructs`). Then
the calibration module:
1. **Find the InstanceKlass vtable by voting.** In the address range of the jvm.dll/.exe
   image we iterate candidates for the vtable pointer; the correct one is the one that
   occurs most often as the first field of objects in the metaspace range
   (there are many classes → its pointer is the most frequent).
2. **Anchor on known classes.** For `java/lang/Object` the name is known, that
   super=null, and the set of methods. We look for an object whose `_name` (by the
   candidate offset name_off) resolves to the Symbol "java/lang/Object".
3. **Walk the chain and validate.** From the found InstanceKlass →
   `_constants` → ConstantPool; the CP has a back-ref `_pool_holder`, which must point
   back to the same InstanceKlass — this is the lock that cuts off wrong offsets. Then
   Method→ConstMethod→CP, a full cross-check. We iterate offset candidates and take the
   first set consistent along the whole chain.
4. **Cache.** Dump scans are slow (~55s) — put the calibration result into a file,
   otherwise every probe rescans.

Compute the dynamic metaspace range (`in_metaspace`) from the min/max addresses of the
found vtables, excluding the jvm image — don't hardcode the address.

IMPORTANT: the calibration heuristic is a double-edged sword. On some builds it triggers
FALSELY (gives wrong offsets), while export-based resolve is honest there — so
calibration must be DISABLED. Judge by the project: no exports → calibration; there are
→ exports.

### 4.3 Calibration probes (probe commands)
Keep a set of probes in the reconstructor so you can probe offsets against the dump by
hand: dumping raw bytes around the supposed field (`cpcache <class>`, `methprobe <class>`,
general calibration dumps). You can see with your eyes where the name is, where the
pointer is, where the length is. Order: first `_name` (look for an ASCII Symbol), then
from it `_super`/`_constants`/`_methods`, then the ConstMethod tail by `code_size`
(a small reasonable number) and `codes` (meaningful opcodes <0xca).

### 4.4 Offset reference by build

These are starting hypotheses from past projects. Do NOT copy blindly — verify against
the dump. All values in bytes, from the start of the corresponding structure.

**JDK 8 (old 1.8.9 clients).** A different world: the class encoding is different, it is
usually easier to take the bytes from the heap (section 7.2 / 8.1) than to reconstruct
the metaspace.

**JDK 21 — the "legacy cpCache" build:**
- Klass: `_name` +0x18, `_super` +0x30, access +0xa4, InstanceKlass `_methods` +0x168.
- ConstantPool: tags +0x08, header ~80, length +0x3c.
- Method: `_constMethod` +0x08, access +0x30.
- ConstMethod: code_size +0x22, name_index +0x24, sig_index +0x26, codes +0x38.
- ConstantPoolCache: **legacy `ConstantPoolCacheEntry`** (stride 32, cp-index in the
  low 16 bits of `_indices`, header ~64), NOT resolved arrays.

**JDK 21 — the "resolved arrays" build:**
- ConstMethod tail (+2 vs JDK17): code_size 0x22, name_index 0x24, sig_index
  0x26, max_stack 0x2a, max_locals 0x2c, size_of_parameters 0x2e, codes 0x32.
- ConstantPoolCache: `_constant_pool` +0x08, reference_map(Array<u2>) +0x18,
  ResolvedIndyEntry +0x28 (stride 16, cp-idx +10), ResolvedFieldEntry +0x30
  (stride 24, cp-idx +14), ResolvedMethodEntry +0x38 (stride 24, cp-idx +16).

**JDK 25 (internal-adhoc builds):**
- Klass: name 0x18, super 0x78. InstanceKlass: annotations 0xc8, constants 0xe0,
  methods 0x190.
- Method: const_method 0x08, access_flags 0x2c.
- ConstMethod (reordered!): size 0x38 (in words), constants 0x28, flags 0x3c,
  code_size 0x42, name_idx 0x44, sig_idx 0x46, idnum 0x48, max_stack 0x4a,
  max_locals 0x4c, params 0x4e, codes 0x58.
- ConstantPool: tags 0x08, cache 0x10, holder 0x18, major 0x30, srcfile 0x36,
  slot_base 0x48.
- CPCache: indy +0x28 (str16, cp10), field +0x30 (str24, cp14), method +0x38
  (str24, cp16). (This is cpCache +8 relative to JDK28.)

**JDK 28 (internal-xmake):**
- Klass: name 0x18, super 0x80. InstanceKlass: constants 0xd8, methods 0x170.
- ConstantPool: tags 0x08, cache 0x10, pool_holder 0x18, slot_base 0x68.
- ConstMethod: constants 0x08, code_size 0x30, name_index 0x32, sig_index 0x34,
  max_stack 0x38, max_locals 0x3a, codes 0x48.
- Method: const_method 0x08, access_flags 0x2c (at 0x28 there is internal garbage 0xfffe).
- ConstantPoolCache: shifted by −8 (no `_archived_references_index`):
  `_constant_pool` +0x00, ref_map +0x10, indy +0x20, field +0x28, method +0x30.
  Strides: RFE 24/cp+14, RME 24/cp+16, RIE 16/cp+10 (verify against the dump — in master
  RME is sometimes 32/20, in a specific build 24/16).

**JDK 23 (custom forks, e.g. GayVM/oxxxde):**
- ConstantPool: cache +0x10, entries base **+0x48** (JDK21-resolved had +0x50).
- ConstMethod: code_size +0x22, bytecode +0x38 (verify — decoy at +0x1C=5/37).
- Hidden classes (hidden, `Lookup.defineHiddenClass`): `_name` is a suffixed
  Symbol, NOT found by the plain name. Resolve through the ConstantPool: look for Utf8
  `*.java` (SourceFile) → `CP_base = this_slot − 0x58`.

**JDK 16 (AkrienAntiLeak/ArgentozVM):** Method `_constMethod` @Method **+0x40** (NOT
+0x08!), access_flags @+0x28; ConstMethod fields RELATIVE TO R=`_constants`: bytecode
R+0x10, code_size R−0x10, name_idx R−0x0e, sig R−0x0c; `_operands`
(BootstrapMethods) @CP+0x20; vtable exports (`??_7Class@@6B@`) are intact even with
`gHotSpotVMStructs` erased → exact VAs without signature search.

**JDK 8:** FieldInfo = 6 u2/field (7 if generic-signature — an extra generic_sig_idx);
`_fast_iaccess_0/aaccess_0/faccess_0` (0xdd-0xdf) = **4 BYTES** (`op, embedded
getfield, 2b cache-idx`) → a wrong 3-byte length = +1 drift on every
`this.field` (~700 classes); `_fast_iload2` (0xe1) is also 4 bytes.

**JDK21 custom forks (shifts "drift" AS A WHOLE, not uniformly) — real values seen in
dumps:** super +0xb8 (not +0x78), constants +0x150 / +0xC8 (not +0xD0),
methods +0x200 / +0x168 (not +0x180), CP entries base +0x60 (not +0x48), ConstMethod
bytecode +0x50 / +0x88 (not +0x38), Method access_flags(u16) +0x30 (at +0x28 there is
a garbage pointer; ~63k methods falsely abstract), Symbol body +0x18 (not +6),
Klass name +0x20 (not +0x18). These are NOT hypotheses to copy, but PROOF
that calibration against anchor classes (Object/String) is mandatory for every build.

**Custom Symbol layout (Sk3dGuard and similar):** instead of the standard
`[u4 hash+refcount][u2 length][utf8]` there is `[u4 length][utf8]` (no hash) —
it breaks the whole name reader. Plus per-launch random XOR keys on Symbol-ptr / length /
ConstMethod name_idx / desc_idx / code_len (each structure has its own key) → calibrate
against a method with a provably-preserved opcode.

The layout reference is the `openjdk/jdk` sources on GitHub (`constMethod.hpp`,
`resolvedFieldEntry.hpp` etc.), but always verify strides and field presence against the
specific build: custom JVMs change them.

## 5. Minidump analysis: the mechanics

A Windows minidump is not raw memory but a container of streams. All you need from it is
to turn the virtual address (VA) where a JVM structure lies into a file offset and read
the bytes. Let's go through the format step by step.

### 5.1 Container layout
```
MINIDUMP_HEADER @0:
  u32 Signature      = 'MDMP' (0x504D444D)
  u32 Version
  u32 NumberOfStreams
  u32 StreamDirectoryRva   -> array of MINIDUMP_DIRECTORY

MINIDUMP_DIRECTORY (at StreamDirectoryRva, NumberOfStreams records, 12 bytes each):
  u32 StreamType           # 0x0009 = Memory64ListStream; 0x0004 = ModuleListStream
  u32 DataSize
  u32 Rva                  # offset of the stream data in the file

MINIDUMP_MEMORY64_LIST (at the Rva of stream 0x0009):
  u64 NumberOfMemoryRanges
  u64 BaseRva              # file offset where the DATA of all regions starts, back to back
  then NumberOfMemoryRanges * MINIDUMP_MEMORY_DESCRIPTOR64:
     u64 StartOfMemoryRange   # virtual address of the region
     u64 DataSize             # size of the region
  # file offset of region i = BaseRva + sum of DataSize of regions 0..i-1
```
The key point of Memory64List: the descriptors do NOT store the file offset of each
region — only the VA and the size. The offset is computed cumulatively from `BaseRva`.
So when building the index you must walk the descriptors in order and maintain a
running `fileOff += prev.DataSize`.

Modules (needed to find the ImageBase of jvm.dll/.exe for the native lift):
```
MINIDUMP_MODULE_LIST (stream 0x0004):
  u32 NumberOfModules
  then MINIDUMP_MODULE[]:
     u64 BaseOfImage          # ImageBase of the module in memory
     u32 SizeOfImage
     ... (VersionInfo etc.)
     u32 ModuleNameRva        # at +0x04 from the start of the record in some layouts;
                              # name = MINIDUMP_STRING (u32 len + UTF-16LE)
```
In practice: the module name is a MINIDUMP_STRING at an RVA; you read the u32 length
(in bytes), then UTF-16LE. That is how you find the `jvm.dll`/`client.dll` record and
its `BaseOfImage`.

### 5.2 A VA→file reader in Rust
The main tool is in Rust (fast mmap of a multi-gigabyte dump, precise byte handling).
The skeleton of a reader that exposes `read(va, len)`:
```rust
use std::fs::File;
use memmap2::Mmap;

pub struct Region { pub va: u64, pub size: u64, pub file_off: u64 }

pub struct Dump { map: Mmap, regions: Vec<Region> }

impl Dump {
    pub fn open(path: &str) -> std::io::Result<Dump> {
        let map = unsafe { Mmap::map(&File::open(path)?)? };
        let rd = |o: usize| u32::from_le_bytes(map[o..o+4].try_into().unwrap());
        let rd64 = |o: usize| u64::from_le_bytes(map[o..o+8].try_into().unwrap());
        assert_eq!(&map[0..4], b"MDMP");
        let n_streams = rd(8) as usize;
        let dir = rd(12) as usize;
        let mut regions = Vec::new();
        for i in 0..n_streams {
            let e = dir + i*12;
            let (ty, _sz, rva) = (rd(e), rd(e+4), rd(e+8) as usize);
            if ty == 0x0009 {                          // Memory64List
                let count = rd64(rva) as usize;
                let mut foff = rd64(rva+8);             // BaseRva
                let mut p = rva + 16;
                for _ in 0..count {
                    let va = rd64(p); let size = rd64(p+8);
                    regions.push(Region { va, size, file_off: foff });
                    foff += size; p += 16;
                }
            }
        }
        regions.sort_by_key(|r| r.va);
        Ok(Dump { map, regions })
    }

    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        let i = self.regions.partition_point(|r| r.va <= va);
        let r = self.regions.get(i.checked_sub(1)?)?;
        if va >= r.va && va + len as u64 <= r.va + r.size {
            let off = (r.file_off + (va - r.va)) as usize;
            return Some(&self.map[off..off+len]);
        }
        None                                            // address not covered by the dump
    }

    pub fn u64(&self, va: u64) -> Option<u64> {
        self.read(va, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }
}
```
`partition_point` over the sorted regions gives an O(log n) VA resolve. For scanning the
metaspace it is also handy to expose an iterator over all regions (to search for
vtable pointers across the whole address space).

### 5.3 A Python reader for Unicorn
For the native lift (section 8, Appendix C) you need the same `read(va, n)` from Python —
Unicorn pulls pages from the dump on demand. The logic is identical: parse the
Memory64List, keep a list of `(va, size, file_off)`, `read` = binary search of the
region + `seek`. Keep both readers in agreement (the same index layout).

### 5.4 Extract a native module from the dump
The reconstructor's `moddump` command takes the `BaseOfImage`+`SizeOfImage` of the
needed module from the ModuleList, cuts out the region and rebuilds a valid PE (sections
by SectionAlignment, header fixup via `lief`). Needed for reversing the native
decoder/loader and for lifting FFI methods.
```
moddump 'natives\client.dll' out   # base+size from MINIDUMP_MODULE, cuts out the PE
```

### 5.5 A full process dump vs a minidump
A full dump (not a minidump) is a linear memory map, the reader is simpler (a single
offset), but the file is heavier and slower. The reconstruction mechanics are the same:
the only difference is the VA→file layer. Abstract the reading behind a trait
`MemReader { fn read(va,len) }`, and all the rest of the code (scan, structure parsing,
lift) does not depend on the dump format.

---

## 6. Bytecode de-rewrite (quickened → standard)

In the metaspace the bytecode is "rewritten": at link time the interpreter replaces some
opcodes with fast forms and substitutes cpCache indexes instead of CP indexes. You cannot
simply copy the bytes — you would get an invalid class. You need to bring back the
standard form.

### 6.1 What to unwrap
- `getfield/putfield` ← `fast_*getfield/putfield` — restore the regular ones; the operand
  points into a ResolvedFieldEntry → take the cp-index from there.
- `invokevirtual/special/static/interface` — the operand is the index of a
  ResolvedMethodEntry → take the cp-index.
- `fast_invokevfinal` → `invokevirtual`.
- `invokedynamic` (0xba) — the operand is the index of a ResolvedIndyEntry → cp-index.
  **JDK21+ subtlety: the operand is stored DIRECTLY (raw), not as a complement.** In
  derewrite: `cidx = raw`, NOT `!raw`. An error here kills ~95 classes at the class
  level (lambda handling). Older JDKs sometimes had a complement — verify.
- `ldc/ldc_w` ← `fast_aldc/fast_aldc_w` — the operand via reference_map/resolve.
- `_nofast_*` → the regular ones (nofast_getfield/iload…).
- `_return_register_finalizer` → `return`.
- `_fast_aload_0` → `aload_0` and the rest of the stock fast set → the equivalent.

Keep the unwrapping of the stock JDK set in an opcode table for the specific build.
cpCache operands are remapped ONLY for linked/executed classes;
force-loaded ones (section 9) keep the original CP indexes, the maps are empty — they
don't need operand de-rewrite.

### 6.2 Opcode remap — a special case
Some builds insert a custom opcode marker (e.g. at 0xcb, len 1, placed at class PARSING
time, present even in unlinked classes) and shift the WHOLE stock fast set by +1:
0xcc=fast_agetfield (was 0xcb), 0xdd=fast_aload_0, 0xe4=invokevfinal,
0xe9=return_reg_finalizer, 0xee=nofast_iload etc. To crack it — dump
`Bytecodes::_name`/`_lengths` from jvm.dll (find them by the file offsets of the name/
length tables) and compare with the stock. Tool patches: marker→nop ALWAYS (before the
maps gate, important for unlinked classes); the rest fast→their own standard
equivalent, all lengths +1. Do NOT confuse this remap with encryption: a body with a
remap is real bytecode (entropy is bimodal 2.9–7.9, starts with getstatic/goto,
ends with athrow/return); a body with bytes >0xee and high entropy is already
ciphertext (section 8).

---

## 7. Emitting correct Code: the subtleties that decide everything

The custom JVM loads the bytecode in the dump with `verify off`, so it allows itself
things the stock one would not let through. That is exactly where a naive emit breaks.
The techniques that raised the quality from 34% to 99%:

### 7.1 Code length (needed)
`code_size` in ConstMethod is often **truncated** (the method ends mid-expression) or,
conversely, stretches into garbage. Don't trust it as a boundary. Look for the
**natural end**: the first terminator (return/areturn/…/athrow/goto/goto_w) that covers
all branch targets BEFORE it; do NOT count switch as the end (the flattening
tableswitch dispatcher). Builds have been seen where branches go BEYOND the
`code_size` boundary (the return lies there) — the emit must be extended to the
targets of the branches/handlers. Read a window of `code_size+64`, progressively
(the dump region may have cut the tail): try `code_size+64 .. +0`.

### 7.2 Exception table
pc in ConstMethod is often unaligned/broken. Do NOT "snap" to the nearest instruction —
FILTER: emit only records where start/end/handler land exactly on the instruction
boundaries of the already emitted code. Otherwise a strict decompiler chokes.

### 7.3 Canary (anti-dump)
There is junk at position 0 of the method: a single garbage opcode + exactly 5 nops
(breaks the stack, but verify off — the JVM survives). Neutralize it BEFORE computing
the length: nop the first instruction if it consumes the stack
(arith/switch/store/if/getfield/invoke-with-arg/jsr/ret) OR it is op+5nops. Nop the whole
instruction (by step length, cap 6), not just the opcode — otherwise `step()` stumbles
on the canary (0xca breakpoint, jsr_w) and `needed` returns a truncated code.

### 7.4 Access flags and garbage
Strip the garbage flags `native/abstract/bridge/strict` from methods with code
(mask 0x0d40), normalize visibility (exactly one of public/protected/private).
Don't emit fake protection annotations (garbage ones are sometimes planted).

### 7.5 Dead code
Nop out unreachable sections. Plus `-noverify` on the subsequent run, if it is
also a mod.

### 7.6 Parallelism
Scan the dump in 32 MB chunks across all cores + a pool for assembling classes. A batch
of ~660 classes: 6:23 → ~54s (7x). A progress bar with ETA.

## 8. Method body encryption: WHERE decryption happens

The main branching question: **where is the decryption?** Whether you need a metaspace
reconstructor at all, or everything is simpler, depends on it. Determine it in order:

### 8.1 Decryption in a Java loader (Fabric/transformer/custom ClassLoader): mechanics
This is the first question that decides the whole subsequent strategy: **are the classes
decrypted by the native JVM or by Java code?** If by Java code — the task is drastically
simpler, and no metaspace reconstructor is needed.

**How it works in a Java loader.** Class loading in the JVM always goes through
`ClassLoader.defineClass(name, byte[], off, len)` — its input is an already finished
classfile (`CAFEBABE...`). So if the class is encrypted on disk, then somewhere in Java,
between "read the resource" and `defineClass`, there is code that turns the ciphertext
into a valid classfile. The points where it lives:
- **A custom `ClassLoader.findClass/loadClass`.** Reads its own encrypted resource,
  XOR/AES it, calls `defineClass`. Look in the JAR for a class extending
  `ClassLoader`/`URLClassLoader`/`SecureClassLoader`, with resource reading and a
  crypto transform before `defineClass`.
- **Fabric: `KnotClassLoader` + `MixinTransformer`/`GameTransformer`.** Fabric loads the
  game with its `KnotClassLoader`; classes pass through a chain of transformers (Mixin
  `IMixinTransformer.transformClassBytes`, fabric-loader `GameTransformer`). The
  protection often hangs ITS OWN transformer into this chain:
  the `byte[]` is decrypted inside `transformClassBytes(name, bytes)`.
  So the decryption is an ordinary Java method that takes and returns a `byte[]`.
- **`Instrumentation`/a premain agent.** `ClassFileTransformer.transform` — also Java,
  also `byte[]`→`byte[]` before define.

**Three ways to take it (in increasing effort):**

1. **Heap scan for CAFEBABE (from the dump, the cheapest).** If the loader keeps the
   decrypted classfile in a `byte[]` (and it almost always puts it there before
   `defineClass`), these arrays live in the Java heap. In HotSpot a `byte[]` is an object
   with a header (mark word + klass ptr) + `jint length` + data. Scan: look for the
   `CA FE BA BE` signature in the heap regions, step back to the array header,
   read `length`, cut `length` bytes → that is a ready `.class`. Validate it by the fact
   that a correct minor/major version and a reasonable constant_pool_count follow.
   This is how clients whose decryption is in Java are taken. Careful: some classes may
   be defined straight from a native buffer (no bytes in the heap) — you can't get them
   this way, for those there is 9.2 (JVMTI).
2. **Transformer hook on a live process (JVMTI/agent).** Set
   `RetransformClasses` or a breakpoint on the transformer method (see 9.2) and drain the
   returned `byte[]` — you get exactly what goes into `defineClass`, for ALL classes
   regardless of the loader.
3. **Pull out and call the decryptor itself.** If the decryption is a pure Java method
   (`byte[] decrypt(byte[])` with a key from a resource/constant), you can take it from
   the JAR and run it offline on the encrypted resources: spin up a mini-runner, load the
   decryptor class by reflection, feed it every encrypted resource.

**How to tell a Java decrypt from a native one (diagnostics):**
- In the JAR there is a class extending ClassLoader/transformer, with resource reading and
  crypto before `defineClass` → **Java side**, work per 8.1.
- There are no classes in the JAR at all or they are stubs, and `jvm.dll` is custom
  (structures reordered, exports cut) → **native side**, you need the metaspace
  reconstructor (8.2) and possibly decoder emulation (8.4).
- Hybrid: the classfile is decrypted in Java (structure open), but the method BODIES are
  encrypted separately and are unwrapped natively at call time → both: bytes from the
  heap give the structure + hot bodies, cold bodies are topped up per 8.4.

This is the direct answer to "decrypt in the fabric loader or in the jvm": is there a
class in the Java code that turns ciphertext into `CAFEBABE` BEFORE `defineClass`. If
there is — Java side, no offset hunting needed. If not — native side, we go into the
metaspace.

### 8.2 Decryption in the native JVM (lazily at execution)
If `jvm.dll` is custom and the method bodies in the metaspace are encrypted but are
decrypted by the interpreter on the FIRST call — this is the toughest layer. From a
single dump: hot methods are already decrypted (they lie in the metaspace in the open),
cold ones are ciphertext. Signs of a cold one: `ConstantPoolCache == 0`, opcodes
>0xc9/high entropy, the body does not end with a terminator.

Three ways to top up the cold ones:
1. **Exercise more code paths before the dump** (poke the client) and re-dump.
2. **Reverse the native decoder** and emulate it on the dump memory (section 8.4).
3. **Force-decode** (if the decoder is deterministic — section 8.4).

### 8.3 Body encryption schemes (what has been seen)
- **splitmix64 XOR keystream.** The bytecode is XORed with a keystream = the standard
  splitmix64(seed) in 8-byte steps (mix constants 0xbf58476d1ce4e5b9 /
  0x94d049bb133111eb, gamma 0x9e3779b97f4a7c15). splitmix64 is invertible → from
  known plaintext (e.g. a record `equals` = `2a 2b ba <indy> ac`)
  the exact seed is recovered. Unobfuscated methods: keystream=0
  (seed=invSplit(0)=0x7ff61ba9c004ebf8). Open question in one of the projects:
  the per-method seed formula (depends on the class, but is not a simple identity hash) —
  it is computed as a function of the obfuscated native code; the path is emulating the
  seed computor in Unicorn.
- **ISR (Instruction Set Randomization).** Opcode =
  `table256[ fold(splitmix64_mix(pos*0x9e3779b9… ^ KEY)) ^ cipher ]`; operands =
  `(cipher−A)*B` with per-class A,B. KEY/table/A/B are computed ON THE FLY per class
  (they are not in the dump — a function of the class identity + the HWID key). The
  decoder in jvm.dll: a native export hook → class decoder (rcx=ik, gated on a class
  flag bit) → per-method decoder (itself obfuscated with flattening). The implementation
  runs as an injected native runtime class.
- **Opcode remap.** Not encryption but a permutation of the set (section 6.2). Plus on
  top of it part of the bodies is genuinely encrypted (high entropy, bytes >0xee).
- **VM virtualization of bodies** (GayVM/Voile/JTC/VxLang VM). The method body is not
  bytecode but bytecode of a VIRTUAL machine (opcodes 0xEE-0xFF, a prologue marker,
  per-opcode salts, global seeds in jvm.dll). This is not "decrypt" but de-virtualize:
  reverse the interpreter or live-capture with dispatch. Details and the split into
  recoverable (plain non-prologue) / live-only (scrambled without per-address salt) —
  section 18.4 and the concrete de-virt recipe in Appendix M.
- **Feedback-cipher / repeating-XOR class / session-key / per-method gate-bit** —
  other schemes encountered, specific to MC cheats, catalogued with countermeasures
  in section 18.3 (there too — why one known CAFEBABE cracks the repeating XOR key
  and how to get session/masterKey from runtime memory).

### 8.4 Lifting encrypted bodies = emulating the decoder in Unicorn
This is "rewrite native methods from the dump" in the sense of decryption. The idea: not
to reverse the crypto algorithm by hand, but to EXECUTE the JVM's own native decoder on
the dump memory — it will decrypt by itself. The harness skeleton is in Appendix C;
recovering names/strings with the same technique — C.3; the ready Rust base for this
(dump mapping + Win64-call + JVM-walker), which is adapted to the specific VM —
Appendix N (sp1cy-mulator).

How (following the ISR case, working folder: dump reader + emulation harnesses):
1. Lazy paging: Unicorn maps pages on demand from the dump, so the native code sees both
   its own code and the keys and the tables — everything that was in memory.
2. Run the class decoder on a cold class → it decodes all methods of the class
   in place (verified by the bytecode validity sign on the output).
3. Capture the per-class parameters (key + pointers to constants/table) at the
   loop-RIP inside the decoder → then you can call the per-method decoder directly on
   any method.
4. **Check determinism.** If key/constants = a function of ONLY the class identity
   (name+HWID), independent of the bytecode and of the decode state (two decodes of the
   same class → the same key; the key has 0 occurrences in the dump — it is computed),
   then the capture works for ANY class, including hot ones: force a per-class decode by
   resetting the class flag (bit0 "not decoded" + the gate bit), grab the key, call the
   per-method decoder.
5. The reconstructor takes the decrypted bytes through the env path: it reads decoded
   instead of the metaspace bytes. IMPORTANT: decoded is pre-link STANDARD bytecode, it
   does NOT need de-rewrite (derewrite would break the operands). Integration:
   try-dump-first (if the bytes from the metaspace are valid — take them, otherwise
   decoded with EMPTY maps).

Be careful with Unicorn: SSE flags (comiss/cmpss) in some versions (2.1.4) glitch
on repeated calls — check float comparisons in isolation.

### 8.5 The limit of decryption: FFI native ≠ ciphertext
If the key is correct but the method decodes to garbage — this is NOT ISR ciphertext but
an **FFI-native** method: the implementation runs natively (an injected native runtime
class, or a separate `client.dll`), and the bytecode in the metaspace is a decoy. The
decoder cannot pull it out — you need a native→Java lift (section 10). That is how a
batch of methods was left in the ISR case — it is not a key bug, but the boundary between
"decrypt" and "lift the native code".

---

## 9. Topping up missing classes

Only loaded classes are taken from a single dump. Some were not loaded in the session
(didn't need to be). Two techniques to take everything.

### 9.1 The jopt-simple patch (force-load before the dump)
Idea: before taking the dump, force the JVM to load ALL classes so that they land in the
metaspace. jopt-simple is almost always on the client's classpath and parses arguments at
startup — a perfect entry point. Skeleton — Appendix D.2.
- Build a patched `jopt-simple-<ver>.jar`: the original + a "definer" class
  (a daemon thread), invoked from `OptionParser.parse` (or injection into `<clinit>` of
  `OptionParser`/`AbstractOptionSpec`/`OptionSet` via the Class-File API).
- The definer finds the right ClassLoader (e.g. Fabric KnotClassLoader — by probing)
  and does `Class.forName(name, false, loader)` for all names from the resource list.
  The custom JVM defines and (partially) decodes them.
- Trigger the client, take a NEW dump — the tool picks up the new jvm base automatically
  through the exports. That is how hundreds of missing classes are recovered up to full
  coverage.

Pitfalls:
- The file name on the classpath must not change (`jopt-simple-<ver>.jar` must stay).
- An anonymous `Runnable` compiles into a separate `$1.class` → NoClassDefFound. Make it
  `implements Runnable` — one class.
- **Java 8:** the patch jar must NOT be rebuilt with the `jar` tool of a new JDK — the
  old JVM won't open such an archive (findResource=null → NoClassDefFoundError on the
  first class). Build with the system `zip` over the original, replacing only the needed
  entries. Compile with `javac --release 8 -XDstringConcat=inline`.

### 9.2 A JVMTI agent — take the bytecode from a live process
The most reliable option when classes are defined from a native buffer and are not in
the heap (some classes are defined by the native loader directly). JVMTI sees
EVERYTHING regardless of the loader. Skeleton — Appendix D.1.
- A native agent library (convenient as a Rust cdylib, cross-compiled for Windows
  via mingw). Through `GetLoadedClasses` + `RetransformClasses` +
  `ClassFileLoadHook` it takes the bytecode of all target classes and writes it into a jar.
- Better to load it as `-agentpath` (Agent_OnLoad): there `can_retransform_classes`,
  `can_generate_breakpoint_events`, `can_access_local_variables` are onload-only
  (with a late inject some capabilities are unavailable, error code 98).
- Separate objects (e.g. a byte[] that the loader parses but does not define
  as classes): on `ClassPrepare` set a JVMTI breakpoint on the needed method, in the
  handler `GetLocalObject` + `GetByteArrayRegion` → jar.
Why JVMTI and not the jopt approach: if the client loads classes with its own native
loader, you can't reach its instance from Java. JVMTI is at the JVM level and sees
everything. This is the technique for a LIVE process; JVMTI won't help from a dump.

## 10. Lifting native methods (native → Java rewrite)

When a method is really `native` (FFI/AOT), there is no bytecode — you have to recover the
logic from the compiled native function. This is a separate reverse-engineering
discipline. Understanding comes from how these methods are BORN (a typical
bytecode→native transpiler):

### 10.1 How the transpiler produces native (so you can unwrap it back)
The transpiler takes a Java method and unrolls the stack machine into direct C code with
`goto` labels by instruction indexes; the method is marked `ACC_NATIVE`, the Code is
deleted. So the native function is literally the same logic, only:
- Pure arithmetic → bare machine code (Win64 ABI: parameters r8/r9/xmm2/xmm3…).
- Objects/fields/calls → JNIEnv sequences: `FindClass` / `GetMethodID` /
  `GetFieldID` / `CallStaticX` / `GetObjectField`… The class/method/field names and
  signatures are arguments of these calls.
- invokedynamic (string concat, lambdas) — via outlining: a synthetic static
  method with the same indy, the native code calls it as an ordinary static one.

### 10.2 The easy case (unhardened native)
If the lib is NOT stripped, exports = `Java_<class>_<method>` (a full method map), the
JNI strings in `.rdata` are in plain text — the lift is almost mechanical:
- Exports give the list of methods and their classes.
- We read the JNIEnv sequences and map back: `FindClass("X")` +
  `GetMethodID("m","(…)…")` + `CallVirtual` → `invokevirtual X.m`. We restore
  the method structure.
- Pure functions: grab the machine code, emulate it in Unicorn, compare input/output
  bit for bit with the original. That is how pure arithmetic functions are lifted — the
  result is identical without the DLL.

### 10.3 The hard case (hardened native)
A production stack hides all of this:
- No `Java_*` exports — the bodies are static (`fN`), bound via
  `RegisterNatives` in `JNI_OnLoad`, only `JNI_OnLoad` is exported. → The method map
  must be built from the `RegisterNatives` arguments (parse the
  `JNINativeMethod{name, sig, fnptr}` array in onload).
- No plaintext JNI strings — the names are in a per-build XOR blob, the IDs are resolved
  once in `JNI_OnLoad` and cached (`gClass/gMeth/gFld`), the plaintext is wiped with
  memset. → Decrypt the blob (emulate onload in Unicorn until the cache is filled, grab
  `gClass/gMeth/gFld`), then you can see which fnptr calls what. (KEY/buffer are usually
  `volatile` — otherwise -O2 would fold the decrypt into compile time; since it is
  volatile, the real decrypt is in the binary, emulate it.)
- strip, `-fvisibility=hidden`, no DWARF. → Only emulation + I/O comparison.

The hard-lift strategy: emulate `JNI_OnLoad` in Unicorn with JNIEnv stubs, log all
`RegisterNatives`/`FindClass`/`GetMethodID` → get the map (fnptr → Java signature). Then
either emulate each fnptr (pure), or parse the JNI sequence (object) and assemble an
equivalent Java method. If the task is to get the logic OUT of the artifact, don't peek at
the transpiler sources on the side; work from the binary.

### 10.4 When the lift is not needed
If the native part is only auth/strings/heartbeat, and the features are pure Java with
indy obfuscation, you can boot offline by stubbing auth at the Java level and LEAVING the
native methods native (running on the native custom JVM where the native code is alive).
Then the lift is postponed. Decide by what actually blocks the goal.

---

## 11. The route (playbook)

Decision tree from the input to the result:

```
1. Magic of the classes in the JAR?
   ├─ CAFEBABE, classes in place  → this is not classfile protection, decompile directly.
   ├─ Own magic / stub classes → real code at runtime, a dump is needed. ↓

2. Is there a dump?
   ├─ No, but the process can be started → JVMTI agent (9.2) OR jopt-patch+dump (9.1).
   └─ There is a .dmp → ↓

3. Where is the decryption? (section 8)
   ├─ In a Java loader (Fabric/transformer/ClassLoader)
   │     → heap scan for CAFEBABE (7.2/8.1). Often this is enough.
   ├─ In the native JVM (custom jvm.dll, bodies encrypted lazily)
   │     → metaspace reconstructor:
   │        a. offsets (section 4: exports or calib)
   │        b. de-rewrite (section 6) + correct emit (section 7)
   │        c. hot methods come out immediately; cold ones = ciphertext
   │        d. top up the cold ones: decoder emulation (8.4) / more code paths /
   │           jopt-patch+re-dump
   └─ FFI native (bytecode = decoy) → native→Java lift (section 10).

4. Validate: CFR/Vineflower/javap. Broken/cold methods → native stubs,
   the class remains decompilable (section 12).

5. Report: X/Y classes clean, what is left and why (ciphertext of cold ones / FFI native
   / obfuscation that we don't touch).
```

**If the target is a Minecraft cheat/client** (Fabric/Forge, `net/minecraft` calls, a
custom JVM/loader): after steps 1-5 go to the MC specifics — section 14 (architecture and
the inject model: mod / Java loader / native JVMTI / manual-map), section 15 (offline
launch and emulation), section 16 (reconstruction of render/UI/worldgen), section 17
(topping up data with a hot dump / hot-carve / late-attach / inject-hook), section 18
(catalogue of blockers and countermeasures). The key MC fork: a cold dump gives the
logic but NOT the visuals/wiring if they are native/cold → a HOT dump is needed (menu open, in
the world). **If it is a Fabric mod — immediately assemble a Fabric mod (your own
fabric.mod.json, run on vanilla Fabric) and cut out the client's own online layer
(auth/HWID/heartbeat/C2/keyshare) — section 15.7.**

---

## 12. Stubs: a cold/broken method ≠ a failed class

One unrecoverable method must not bring down the decompilation of the whole class.
Detect cold/broken ones and replace with a `native` stub:
- Signs of a valid body (otherwise → stub): opcodes ≤0xc9; CP indexes in
  range; branch targets inside the code; the return opcode type matches the
  descriptor; ldc on a loadable constant; the body ENDS with a terminator;
  load/store index < max_locals. Stack underflow on a STRAIGHT section is also a sign of
  a broken body (but count stack effects descriptor-aware and STOP at the first branch: a
  full CFG-worklist kills ~31% of valid methods, because exception handlers enter with
  depth=1 — do NOT use the worklist, only the linear straight section).
- An invalid method → a `native` stub. Constructors/`<clinit>` → an empty `return`
  body (otherwise the class won't pass even structurally). There must be no false
  positives — check on `java/lang/String` (norm ~3/183 native).
- `strict=false` verify mode: only structural passability (for obfuscation where the
  body is valid but the decompiler chokes) — then we emit it as real code.
There is an OFFLINE_STUB mode (default bodies instead of `native`) — needed for an
offline launch, so as not to catch UnsatisfiedLinkError on a call.

---

## 13. Downstream: offline launch (if asked)

Sometimes the goal is not to "read" but to "run your client offline" as an ordinary
Fabric/Forge mod. This is a separate big piece of work on top of reconstruction:
- The reconstructed jar is for READING; methods with broken bytecode won't pass
  verification. To run it you need the OFFLINE_STUB mode, or run on the native custom
  JVM (where the native code + decryption are native, and we bypass only auth).
- Auth is stubbed at the Java level: rewrite the identity class (username/uid/role/
  hwid/subscription term) via the Class-File API, the native class initialization → no-op,
  LEAVE the bootstrap/lambda (they are pure Java). indy obfuscation works without the
  native part.
- Entry points (`onInitialize`) are often encrypted → stubbed → the client is inert;
  for a live GUI you need the body decryptor (section 8.4) or a launch on the native JVM.
- The native part can be extracted from the dump (`moddump`) and patched separately
  (force auth, skip verify_jar/heartbeat), or a mock server can be raised.
This is a separate track — take it only if you are explicitly asked to "run it offline".
For a Minecraft client all the in-depth mechanics (the stand, NativeShim, generateOopMap,
ctor-scramble, RAWEXEC, x87 anti-emulation, hooks via Fabric events) are in section 15;
reviving render/UI/menu — section 16.

## 14. Minecraft client specifics: architecture and injection points

Reversing an MC cheat client differs from an abstract "pull the classes": you need to
understand HOW the cheat attaches to the game and WHICH layer does what, otherwise the
reconstruction "loads but is dead".

### 14.1 How the cheat gets into the game (4 models)
1. **An ordinary Fabric/Forge mod.** There is `fabric.mod.json`/`@Mixin`/`ClientModInitializer`,
   entrypoints, mixins. Reconstruction + your own `fabric.mod.json` → it loads as a mod.
2. **A custom ClassLoader/agent, but Java.** `KnotClassLoader`+its own transformer, or a
   premain agent. The decryption is Java `byte[]`→`byte[]` (section 8.1).
3. **A native JVMTI layer (NOT a mod).** Sign: 0 references to mixin/@Mixin/
   ClientModInitializer/premain/instrument, but the classes call `net/minecraft`/
   `class_XXXX` directly. Injection/hooks are set by a native DLL via JVMTI (it patches
   the MC methods, sets per-frame callbacks). Then wiring/render/decrypt are IN THE
   NATIVE part, not in the Java bytecode (see 16).
4. **An external manual-map loader.** A separate exe (often disguised as OperaGX.exe/
   a child of the launcher) finds javaw by the WINDOW TITLE (not parent-pid: javaw is a
   grandchild through a dead intermediary), downloads the core from a server, manual-maps
   the DLL into javaw (MEM_PRIVATE, the MZ/PE header ERASED = stealth, a custom
   init-offset, a worker pool, a cookie tag), the core resolves jvm.dll → decrypts the
   classes → defineClass its own way →
   JNI hooks+GL render, then UNMAPS ITSELF (anti-dump: post factum the region is
   empty). Catch the native trace only AT THE MOMENT OF INJECTION (diff of new regions),
   but the decrypted Java client stays in the javaw heap (regions with a high count of
   obf names = clean classes, better than a broken javaw dump).

### 14.2 Package layout and names
- The client is obfuscated into short/non-ASCII packages (`あ`, `sg/*`, `ru/fals3r`,
  `ilIlil`). The core package (Main+packer+native layer) is usually 5-30 classes; the
  client itself is thousands.
- **MC classes in the intermediary namespace** (`net/minecraft`/`class_XXXX`/`method_NNNNN`/
  `field_NNNNN`). The reconstructor often assigns Yarn-like names
  (`blockX`,`render`,`init`). MC method IDs are stable across obfuscations — use them to
  identify code (our `III` ≠ their `III`, but `method_25402` matches).
- **Compare against a WORKING reference build of the same MC version constantly.** A
  different obfuscation seed → the class names won't match, but the STRUCTURE and the
  MC method IDs do. Decompile both, diff the LOGIC, not the names. The reference jar
  (`Fabric <ver>.jar`) + `mappings.tiny` = the ground truth of INTENT.

### 14.3 What is native, what is Java (role map)
Use jarscan to determine: are there `net/minecraft` calls (usually yes), how many `native`
methods and whether they are bound (native_function@+0x58). A typical split in a
natively injected cheat:
- **Java (recoverable):** module logic, configs (gson), categories, UI widgets,
  values. Usually 80-95% of the bytecode is recoverable.
- **Native (to shim/lift):** class/string decrypt, Unsafe memory, per-class
  init hooks, wiring modules into the manager, the per-frame render callback, provision
  of DrawContext into a static, anti-debug/anti-dump, auth/HWID.

### 14.4 Windows pitfalls of obfuscated names
- In the jar thousands of names are invalid as Windows file names (non-ASCII/CJK/starting
  with a digit/differing only in case) → `jar xf`/`unzip` loses some or collides (`net/40c` vs
  `net/40C`, `Il` vs `iI`). **Work with ASM over the jar ITSELF** (ZipInputStream+
  ClassReader), not over unpacked files. Read the exact entry with a case-sensitive
  parser (Python `zipfile` by exact match). Do not print the names into bash/source —
  pass them as code points (`cp:hex,...`), identify the classes STRUCTURALLY (by
  ASCII names of methods/fields).
- Kana in argv breaks tools → force `\uXXXX`; `-Dfile.encoding=UTF-8`,
  `MSYS_NO_PATHCONV=1`, a unicode log reader. Do NOT rebuild the jar via python
  `zipfile` (it corrupts kana names through CP437) — only `jar`.

---

## 15. Offline launch and emulation of an MC client (in depth)

An extension of section 13. The goal is to revive the reconstructed client offline (check
the protection's resilience / get a working client).

### 15.1 The launch stand
- `java @args.txt`; **`-Xverify:none`** is mandatory (the original loaded classes with a
  native loader, bypassing verification; broken/hostile bodies won't load otherwise).
  Fabric knot-classloader; the preLaunch entrypoint drives the boot;
  gameDir/assets/index.
- A clean JDK of the needed version (NOT a custom AntiLeak one). Dedupe the classpath by
  (artifact,classifier); do NOT merge core+natives lwjgl.
- A transient `EXCEPTION_ACCESS_VIOLATION in String.substring (C2)` = a flaky
  JIT crash → `-XX:-TieredCompilation -XX:CompileThreshold=40000`, restart.
- offline-boot may NOT fully initialize the client → opening vanilla sub-screens
  (MultiplayerScreen: ServerList/client=null) crashes — wrap in
  try-catch(Throwable) so that a broken sub-screen doesn't bring down the game.

### 15.2 The native layer shim (NativeShim)
The client is a facade of ~29 native methods; strip ACC_NATIVE and delegate to your own
class:
- Unsafe memory get/put(Int/Float/Long/Double/Object/Boolean) → Unsafe by offset;
  **a WILD READ GUARD** (offset>0x100000→null, otherwise an AV on reading wild memory).
- decryptClass/defineClass/resolveClass → real values; resolveClass(decoy)→
  the real class/enum.
- The interpreter dispatcher (the most-called long-tag fetch+execute) → real
  semantics/value. initModule/anti-debug/anti-dump → no-op.
- Careful: if decryptClass is a stub (returns the `.class` from the jar, not the
  decrypted payload) → the modules get garbage. Real decryption = keys in the
  native DLL, a reimplementation is needed (or a hot dump, section 17).

### 15.3 Strings and hooks
- **Strings:** StringRouter/StringProvider feed the decrypted strings
  (dumped from the heap, hundreds of thousands) to where the native decode used to be.
  Many strings live in the heap as SCATTERED String objects (5-7 duplicates), not
  gathered into an array; the registry in the heap often holds CIPHERTEXT (decryption is
  lazy, transient).
- **Hooks:** if the injection was native JVMTI (0 mixins/agent/events), build the hooks
  YOURSELF through Fabric events: HudRenderCallback / WorldRenderEvents.END /
  ClientTickEvents.END_CLIENT_TICK / ScreenEvents / keyboard. Put the global
  DrawContext into a client static, iterate the manager (Iterable), call the module's OWN
  render/tick base. Do NOT substitute your own HUD.

### 15.4 The manager and the revival order
Instantiate by reflection with `getDeclaredConstructor().newInstance()`; fix null statics
iteratively (parse `"class.field" is null`). Order: preLaunch→packer (fills the
registries/strings)→call the module registrar→your own client entrypoint installs
fabric-api callbacks and runs the modules. Often `<clinit>` of the decode core/manager is
ERASED by anti-dump (the name-Symbol is zeroed) → reconstruct it (`detect_clinit`:
static+()V+putstatic-into-own-static-field+unique → rename to `<clinit>`), otherwise
key=0/array=null and the decode is dead.

### 15.5 generateOopMap and ctor-scramble (make classes EXECUTABLE)
`generateOopMap` runs ALWAYS, even under `-Xverify:none` (the GC-oop-map is needed).
It is fatal with `Illegal class file … in method <init>` on:
- **uninitialized `this`**: `<init>` without super/this-`<init>` → insert
  `aload_0; super.<init>()` at the beginning (super from classCtors, prefer ()V).
  ASM verifiers do NOT catch this, the JVM does.
- **a ref-vs-value conflict of a slot on merge**: the detector is a custom Interpreter
  that throws ONLY on a ref/value conflict of 1-slot values. Do NOT use
  BasicInterpreter/COMPUTE_FRAMES as the detector — they are stricter than generateOopMap
  (they fail on underflow/height in runtime-dead branches, lobotomizing WORKING methods
  like manager.<init>). underflow/height are TOLERATED by generateOopMap.
- **Ctor-scramble** `new X;dup;args;invokespecial Y.<init>`: the first ctor on `new X`
  is ALWAYS `X.<init>`; retarget the owner to the NEW class, not to the JDK super from the
  f1-holder. Real ctor: prefer ()V + `pop` the extra arguments.
- Strip ACC_FINAL from the fields (final = write-guard; putfield to a final in a renamed
  ctor → IllegalAccessError under -Xverify:none). Strip ACC_ABSTRACT from non-interfaces
  that are `new`-ed.
- RAWEXEC mode: for non-decompilable methods emit RAW (unrewritten) bytecode
  instead of normalize/stub → under -Xverify:none it executes the real init logic without
  fatally breaking the interpreter. Keep two jars: canon (verifier-clean, best
  decompilation) and rawexec (faithful execution).

### 15.6 Anti-emulation: x87 and Unicorn
When you emulate the decoder/key resolver in Unicorn (section 8.4), you meet
**anti-emulation via x87**: the seed is run through 80-bit `fsin/fcos/fyl2x/
fchs`, and the result is mixed into the keystream. Unicorn's software f64 does NOT match
the real 80-bit x87 bit for bit → the decode gives garbage. Solutions: (1) execute the real
x87 instructions on the host (inline asm, dump on the same architecture) — your own
mini-emulator with host-FPU (`fp.rs`); (2) COW mapping of the dump pages (`mem.rs`).
Unicorn 2.1.4: SSE comparisons (comiss/cmpss) glitch on repeated calls — isolate
float logic. The sign of x87 anti-emulation: the seed/key does not lie ready in the dump
(0 occurrences), it is computed on the fly, and a Unicorn run of the decoder gives garbage
with correct ABI/addresses.

### 15.7 A Fabric client: assemble the mod immediately and cut the online server (MAIN)
If the client being reversed is a Fabric mod (there is `fabric.mod.json`/`@Mixin`/entrypoints,
model 1 of 14.1), do NOT build your own custom launcher and do not torture yourself with
headless — **pack the reconstruction as an ordinary Fabric mod right away and run it in the
live game**:
- Your own `fabric.mod.json` (id/entrypoints `main`/`client`/`preLaunch` + a `mixins`
  config, if the mixins are intact), put the jar into `mods/`, launch on VANILLA Fabric
  Loader of the needed MC version. Iterate in the real game: the crash trace from a live
  run = a map of the working pipeline (section 16), faster than guessing in headless.
- **AT THE SAME TIME cut out the whole online layer of the client being reversed** (its
  own backend, not the MC servers): auth/license, HWID check, heartbeat,
  C2/webhook/telegram alerts, keyshare requests, `verify_jar`, online-key,
  update-checker. Otherwise the client either won't start offline (hangs waiting for the
  server), or calls home (reveals activity / breaks on a timeout / bans by hash).
  Techniques: no-op the native auth methods (strip ACC_NATIVE → the stub returns
  success + identity constants username/uid/role/term), stub the Java auth classes via
  the Class-File API/ASM, cut the network calls (a Fabric mixin on the client network
  listener, or replacing URL constants with localhost/no-op), skip verify/heartbeat/snooper
  threads, force `authFlag=true`/`banned=false`. Auth in a natively injected cheat is
  usually already removed by the native shim itself (section 15.2).
- Cut ONLY the network/auth perimeter — LEAVE pure Java working (bootstrap/lambda/indy
  obfuscation, module logic). Raise a mock server only if the client crashes without an
  answer to a challenge-response that cannot simply be nopped.
- The delivery result for Fabric: `*-mod.jar` (reconstruction + fabric.mod.json + shims +
  the cut-out online part), placed into `mods/`, loaded by vanilla Fabric — a working
  offline client with no calls to the original's server.

<!--PART-END-->
