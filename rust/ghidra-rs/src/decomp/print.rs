//! `print raw`: port of `Funcdata::printRaw`, `BlockGraph::printRaw`, `BlockBasic::printRaw`,
//! `Varnode::printRaw`, `Address::printRaw` and the `TypeOp*::printRaw` methods (typeop.cc).
//!
//! The C++ writes to one `ostream` whose number base is sticky: printing an address switches it
//! to hex, a block index or a register offset to decimal, and later numbers (a sequence
//! number's counter, a varnode size) come out in whatever base is current. [`Out`] keeps that
//! state so the text matches byte for byte.

use super::block::{BlockBasic, BlockId};
use super::op::{OpFlags, OpId, SeqNum};
use super::opcode::{Opcode, RawForm, Sizes};
use super::varnode::{Space, VarnodeId};
use super::{err, Arch, Funcdata, Result};
use std::fmt::Write as _;

/// The output text and the stream's current base.
struct Out {
    s: String,
    hex: bool,
}

impl Out {
    fn str(&mut self, s: &str) {
        self.s.push_str(s);
    }
    /// `s << n` in the current base.
    fn num(&mut self, n: u64) {
        let _ = if self.hex { write!(self.s, "{n:x}") } else { write!(self.s, "{n}") };
    }
    /// `s << dec << n`
    fn dec(&mut self, n: u64) {
        self.hex = false;
        self.num(n);
    }
    /// `AddrSpace::printRaw` for a 4-byte space: `0x` and eight hex digits, leaving hex on.
    fn addr(&mut self, a: u64) {
        self.hex = true;
        let _ = write!(self.s, "0x{a:08x}");
    }
    /// `operator<<(SeqNum)`
    fn seq(&mut self, seq: SeqNum) {
        self.addr(seq.addr);
        self.s.push(':');
        self.num(u64::from(seq.time));
    }
}

/// Port of `Funcdata::printRaw` once blocks exist (before that it fails, as the C++ does with
/// "No operations to print" when there are no ops; the raw op list is not ported).
pub fn print_raw(fd: &Funcdata, arch: &Arch) -> Result<String> {
    if fd.blocks.list.is_empty() {
        return err("No operations to print");
    }
    let mut p = Printer { fd, arch, out: Out { s: String::new(), hex: false } };
    p.graph()?;
    Ok(p.out.s)
}

struct Printer<'a> {
    fd: &'a Funcdata,
    arch: &'a Arch,
    out: Out,
}

impl<'a> Printer<'a> {
    fn fd(&self) -> &'a Funcdata {
        self.fd
    }

    fn block(&self, b: BlockId) -> &'a BlockBasic {
        self.fd.blocks.block(b)
    }

    /// Port of `BlockGraph::printRaw`: the graph's header (its index, 0), then each block and
    /// the implied gotos between them.
    fn graph(&mut self) -> Result<()> {
        self.out.dec(0);
        self.out.str("\n");
        let list = &self.fd().blocks.list;
        for (i, &b) in list.iter().enumerate() {
            if let Some(&prev) = i.checked_sub(1).and_then(|j| list.get(j)) {
                self.implied_goto(prev, b);
            }
            self.basic_block(b)?;
        }
        Ok(())
    }

    /// Port of `BlockBasic::printRaw`.
    fn basic_block(&mut self, b: BlockId) -> Result<()> {
        let bl = self.block(b);
        self.out.str("Basic Block ");
        self.out.dec(bl.index as u64);
        self.out.str(" ");
        self.out.addr(bl.start);
        self.out.str("-");
        self.out.addr(bl.stop);
        self.out.str("\n");
        for &op in &bl.ops {
            self.out.seq(self.fd().op(op).seq);
            self.out.str(":\t");
            self.op(op)?;
            self.out.str("\n");
        }
        Ok(())
    }

    /// Port of `BlockBasic::printRawImpliedGoto`: a block that flows to a block other than the
    /// next one printed, without a branch op, shows the goto.
    fn implied_goto(&mut self, b: BlockId, next: BlockId) {
        let bl = self.block(b);
        let [out] = bl.outs[..] else { return };
        if out.point == next || bl.ops.last().is_some_and(|&o| self.fd().op(o).opc.is_branch()) {
            return;
        }
        self.out.addr(bl.stop);
        self.out.str(":   \t[ goto ");
        self.short_header(out.point);
        self.out.str(" ]\n");
    }

    /// Port of `FlowBlock::printShortHeader`: `Block_<index>:<start>`.
    fn short_header(&mut self, b: BlockId) {
        let (index, start) = (self.block(b).index, self.block(b).start);
        self.out.str("Block_");
        self.out.dec(index as u64);
        self.out.str(":");
        self.out.addr(start);
    }

    /// Port of `Varnode::printRaw`.
    fn vn(&mut self, id: VarnodeId) {
        let v = self.fd().vn(id);
        let expect = match v.space {
            Space::Iop => {
                self.out.str("i");
                self.out.seq(self.fd().op(OpId(v.offset as u32)).seq);
                4
            }
            Space::Fspec => {
                let call = &self.fd().calls[v.offset as usize];
                self.out.str("f");
                match call.callee().and_then(|e| self.arch.functions.get(&e)) {
                    Some(f) => self.out.str(&f.name),
                    None => {
                        let entry = call.entry;
                        self.out.str("func_");
                        self.out.addr(entry.unwrap_or_default());
                    }
                }
                4
            }
            Space::Sleigh(sp) => self.address(sp, v.offset, v.size),
            // stack varnodes come with the `stackvars` rules (stage R5)
            // JoinSpace::printRaw: the pieces' names
            Space::Join => {
                let names: Vec<String> = self.fd().joins[v.offset as usize]
                    .iter()
                    .map(|&(s, o, z)| {
                        self.arch.register_name(s, o, z).map_or_else(|| format!("r0x{o:x}"), |r| r.0.to_string())
                    })
                    .collect();
                self.out.str(&format!("j{{{}}}", names.join(",")));
                0
            }
            Space::Stack => {
                self.out.str(&format!("s0x{:08x}", v.offset));
                4
            }
        };
        if expect != v.size {
            self.out.str(":");
            self.out.num(u64::from(v.size));
        }
        if v.is_input() {
            self.out.str("(i)");
        }
        if let Some(def) = v.def {
            self.out.str("(");
            self.out.seq(self.fd().op(def).seq);
            self.out.str(")");
        }
        if raw_extra() {
            self.out.str(&format!("<{}>", self.fd().types.print_vn_type(v.ty, v.size)));
        }
        if v.def.is_none() && !v.is_input() && !v.is_constant() {
            self.out.str("(free)");
        }
    }

    /// Port of `Address::printRaw(ostream,int4)`: a register name, else the space's shortcut and
    /// the offset. Returns the size the text implies (the register's, else 4).
    fn address(&mut self, space: u32, off: u64, size: u32) -> u32 {
        if let Some((name, base, regsize)) = self.arch.register_name(space, off, size) {
            self.out.str(name);
            if off != base {
                self.out.str("+");
                self.out.dec(off - base);
            }
            return regsize;
        }
        let sp = &self.arch.sleigh.spaces[space as usize];
        if space == 0 {
            // ConstantSpace::printRaw
            self.out.str("#");
            self.out.hex = true;
            let _ = write!(self.out.s, "0x{off:x}");
            return 4;
        }
        let shortcut = match sp.name.as_str() {
            "register" => '%',
            "unique" => 'u',
            n => n.chars().next().unwrap_or('x').to_ascii_lowercase(),
        };
        self.out.s.push(shortcut);
        self.out.addr(off);
        4
    }

    fn space_name(&self, vn: VarnodeId) -> &'a str {
        let arch = self.arch;
        let idx = self.fd().vn(vn).offset as usize;
        arch.sleigh.spaces.get(idx).map_or("?", |s| s.name.as_str())
    }

    /// `out = ` for ops with an output.
    fn assign(&mut self, op: OpId) {
        if let Some(out) = self.fd().op(op).out {
            self.vn(out);
            self.out.str(" = ");
        }
    }

    /// `(in[from],in[from+1],...)` when there are such inputs.
    fn args(&mut self, op: OpId, from: usize) {
        let ins = &self.fd().op(op).ins;
        if ins.len() <= from {
            return;
        }
        for (i, &v) in ins[from..].iter().enumerate() {
            self.out.str(if i == 0 { "(" } else { "," });
            self.vn(v);
        }
        self.out.str(")");
    }

    /// Port of `PcodeOp::printRaw`, dispatching to the `TypeOp` of the opcode.
    fn op(&mut self, id: OpId) -> Result<()> {
        let fd = self.fd();
        let op = fd.op(id);
        let ins = &op.ins;
        let in_size = |i: usize| ins.get(i).map_or(0, |&v| fd.vn(v).size);
        match op.opc.raw_form() {
            RawForm::Binary(name) => {
                self.assign(id);
                self.vn(ins[0]);
                self.out.str(" ");
                self.out.str(name);
                self.out.str(" ");
                self.vn(ins[1]);
            }
            RawForm::Unary(name) => {
                self.assign(id);
                self.out.str(name);
                self.out.str(" ");
                self.vn(ins[0]);
            }
            RawForm::Func(name, sizes) => {
                let out_size = op.out.map_or(0, |o| fd.vn(o).size);
                self.assign(id);
                self.out.str(name);
                // getOperatorName writes the sizes to its own stream, always in decimal
                let s = &mut self.out.s;
                let _ = match sizes {
                    Sizes::None => Ok(()),
                    Sizes::In0 => write!(s, "{}", in_size(0)),
                    Sizes::In0Out => write!(s, "{}{out_size}", in_size(0)),
                    Sizes::In0In1 => write!(s, "{}{}", in_size(0), in_size(1)),
                };
                self.args(id, 0);
            }
            RawForm::Special => return self.special(id, ins),
        }
        Ok(())
    }

    /// The ops with their own `printRaw`.
    fn special(&mut self, id: OpId, ins: &[VarnodeId]) -> Result<()> {
        let op = self.fd().op(id);
        let parent = op.parent.map(|b| self.block(b));
        match op.opc {
            Opcode::Copy => {
                self.assign(id);
                self.vn(ins[0]);
            }
            Opcode::Load => {
                self.assign(id);
                let space = self.space_name(ins[0]);
                self.out.str("*(");
                self.out.str(space);
                self.out.str(",");
                self.vn(ins[1]);
                self.out.str(")");
            }
            Opcode::Store => {
                let space = self.space_name(ins[0]);
                self.out.str("*(");
                self.out.str(space);
                self.out.str(",");
                self.vn(ins[1]);
                self.out.str(") = ");
                self.vn(ins[2]);
            }
            Opcode::Branch => {
                self.out.str("goto ");
                match parent.map(|b| &b.outs[..]) {
                    Some([out]) => self.short_header(out.point),
                    _ => self.vn(ins[0]),
                }
            }
            Opcode::Cbranch => {
                self.out.str("goto ");
                // out 0 is the fall-through (false) edge, out 1 the branch (true) edge
                let outs = parent.and_then(|b| <[_; 2]>::try_from(&b.outs[..]).ok());
                match outs {
                    Some([_, t]) => self.short_header(t.point),
                    None => self.vn(ins[0]),
                }
                self.out.str(" if (");
                self.vn(ins[1]);
                let flip = op.flags.has(super::op::OpFlags::BOOLEAN_FLIP);
                self.out.str(if flip { " == 0)" } else { " != 0)" });
                if let Some([f, _]) = outs {
                    self.out.str(" else ");
                    self.short_header(f.point);
                }
            }
            Opcode::Branchind => {
                self.out.str("switch ");
                self.vn(ins[0]);
            }
            Opcode::Call | Opcode::Callind => {
                self.assign(id);
                self.out.str(if op.opc == Opcode::Call { "call " } else { "callind" });
                self.vn(ins[0]);
                self.args(id, 1);
            }
            Opcode::Callother => {
                self.assign(id);
                let index = self.fd().vn(ins[0]).offset;
                match self.arch.sleigh.userop_name(index) {
                    Some(n) => self.out.str(n),
                    None => {
                        self.out.str("syscall[");
                        self.vn(ins[0]);
                        self.out.str("]");
                    }
                }
                self.args(id, 1);
            }
            Opcode::Return => {
                self.out.str("return");
                if let Some(&first) = ins.first() {
                    self.out.str("(");
                    self.vn(first);
                    self.out.str(")");
                }
                for (i, &v) in ins.iter().enumerate().skip(1) {
                    self.out.str(if i == 1 { " " } else { "," });
                    self.vn(v);
                }
            }
            Opcode::Indirect => {
                self.assign(id);
                if op.flags.has(OpFlags::INDIRECT_CREATION) {
                    self.out.str("[create] ");
                } else {
                    self.vn(ins[0]);
                    self.out.str(" [] ");
                }
                self.vn(ins[1]);
            }
            Opcode::Multiequal => {
                self.assign(id);
                self.vn(ins[0]);
                if ins.len() == 1 {
                    self.out.str(" ?");
                }
                for &v in &ins[1..] {
                    self.out.str(" ? ");
                    self.vn(v);
                }
            }
            opc => return err(format!("print raw: {opc:?} is made by later stages, not ported yet")),
        }
        Ok(())
    }
}

/// `DECOMP_RAW_EXTRA` (rust/tools/decomp-ref.patch): print raw also shows each varnode's
/// data-type, as the patched reference does (stage S6).
fn raw_extra() -> bool {
    static EXTRA: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *EXTRA.get_or_init(|| std::env::var_os("DECOMP_RAW_EXTRA").is_some())
}
