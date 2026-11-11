// Reference disassembler: Ghidra's own C++ SLEIGH engine, printing in the same format as
// `ghidra-rs disasm [--pcode]`, so the two outputs can be diffed line by line.
// Build and use: see rust/README.md ("Verifying against the C++ engine").
//
// usage: sleigh_ref <x86-64.sla> <raw code file> <base address hex> [pcode]
#include "sleigh.hh"
#include "loadimage.hh"
#include <cstdio>
#include <fstream>
#include <iterator>

using namespace ghidra;

class RawImage : public LoadImage {
  uintb base;
  vector<uint1> &data;
public:
  RawImage(uintb b, vector<uint1> &d) : LoadImage("raw"), base(b), data(d) {}
  virtual void loadFill(uint1 *ptr, int4 size, const Address &addr) {
    uintb off = addr.getOffset() - base;
    for (int4 i = 0; i < size; ++i)
      ptr[i] = (off + i < data.size()) ? data[off + i] : 0;
  }
  virtual string getArchType(void) const { return "raw"; }
  virtual void adjustVma(long adjust) {}
};

struct Line : public AssemblyEmit {
  string text;
  virtual void dump(const Address &addr, const string &mnem, const string &body) { text = mnem + " " + body; }
};

struct Ops : public PcodeEmit {
  Sleigh *trans;
  string text;
  string vn(const VarnodeData &v) {
    char buf[128];
    if (v.space->getType() == IPTR_CONSTANT) {
      snprintf(buf, sizeof buf, "0x%llx:%d", (unsigned long long)v.offset, v.size);
      return buf;
    }
    string name = trans->getRegisterName(v.space, v.offset, v.size);
    if (!name.empty()) {
      const VarnodeData &r = trans->getRegister(name);
      if (r.offset == v.offset && r.size == (uint4)v.size) return name;
    }
    snprintf(buf, sizeof buf, "%s[0x%llx]:%d", v.space->getName().c_str(), (unsigned long long)v.offset, v.size);
    return buf;
  }
  virtual void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) {
    text += "    ";
    if (outvar != (VarnodeData *)0) text += vn(*outvar) + " = ";
    text += get_opname(opc);
    for (int4 i = 0; i < isize; ++i) {
      text += i == 0 ? " " : ", ";
      if (i == 0 && (opc == CPUI_LOAD || opc == CPUI_STORE))
        text += ((AddrSpace *)(uintp)vars[0].offset)->getName();
      else
        text += vn(vars[i]);
    }
    text += "\n";
  }
};

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s <x86-64.sla> <raw code file> <base hex> [pcode]\n", argv[0]);
    return 2;
  }
  bool pcode = argc > 4;
  AttributeId::initialize();
  ElementId::initialize();
  ifstream f(argv[2], ios::binary);
  vector<uint1> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  uintb base = strtoull(argv[3], 0, 16);
  RawImage loader(base, data);
  ContextInternal context;
  Sleigh trans(&loader, &context);
  DocumentStorage store;
  istringstream doc(string("<sleigh>") + argv[1] + "</sleigh>");
  store.registerTag(store.parseDocument(doc)->getRoot());
  trans.initialize(store);
  context.setVariableDefault("addrsize", 2);
  context.setVariableDefault("opsize", 1);
  context.setVariableDefault("rexprefix", 0);
  context.setVariableDefault("longMode", 1);
  AddrSpace *ram = trans.getDefaultCodeSpace();
  uintb a = base, end = base + data.size();
  Line line;
  Ops ops;
  ops.trans = &trans;
  while (a < end) {
    Address addr(ram, a);
    int4 len = 0;
    try {
      len = trans.printAssembly(line, addr);
      if (a + len > end) throw BadDataError("truncated");
      printf("%016llx  %s\n", (unsigned long long)a, line.text.c_str());
      if (pcode) {
        ops.text.clear();
        try {
          trans.oneInstruction(ops, addr);
          fputs(ops.text.c_str(), stdout);
        } catch (LowlevelError &e) {
          printf("    <no p-code>\n");
        }
      }
      a += len;
    } catch (LowlevelError &e) {
      printf("%016llx  (bad)\n", (unsigned long long)a);
      a += 1;
    }
  }
  return 0;
}
