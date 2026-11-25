//! DWARF location expressions as the DWARF importer reads them for a parameter or a local
//! variable: `DWARFExpression.read` (DWARFExpression.java:59-80, DWARFExpressionInstruction.java:47-84,
//! the operand types of DWARFExpressionOpCode.java:29-195), `toString(cu)`
//! (DWARFExpression.java:169-208) and `DWARFExpressionEvaluator.evaluate` (DWARFExpressionEvaluator.java:
//! 352-687) with the value reader `withStaticStackRegisterValues(null, -8)` the importer sets
//! (`useStaticStackFrameRegisterValue`, x86-64.dwarf: `stack_frame register="RBP" offset="-8"`,
//! `call_frame_cfa value="8"`). Only x86-64's register mappings are here.

use super::read::Cursor;

/// The operand types (DWARFExpressionOperandType)
#[derive(Clone, Copy, PartialEq)]
enum T {
    Addr,
    S1,
    S2,
    S4,
    S8,
    U1,
    U2,
    U4,
    U8,
    Sleb,
    Uleb,
    Blob,
    Int,
}
use T::*;

/// DWARFExpressionOpCode: (opcode, enum name, operand types); lit, reg and breg are generated
const OPS: &[(u8, &str, &[T])] = &[
    (0x03, "DW_OP_addr", &[Addr]),
    (0x06, "DW_OP_deref", &[]),
    (0x08, "DW_OP_const1u", &[U1]),
    (0x09, "DW_OP_const1s", &[S1]),
    (0x0a, "DW_OP_const2u", &[U2]),
    (0x0b, "DW_OP_const2s", &[S2]),
    (0x0c, "DW_OP_const4u", &[U4]),
    (0x0d, "DW_OP_const4s", &[S4]),
    (0x0e, "DW_OP_const8u", &[U8]),
    (0x0f, "DW_OP_const8s", &[S8]),
    (0x10, "DW_OP_constu", &[Uleb]),
    (0x11, "DW_OP_consts", &[Sleb]),
    (0x12, "DW_OP_dup", &[]),
    (0x13, "DW_OP_drop", &[]),
    (0x14, "DW_OP_over", &[]),
    (0x15, "DW_OP_pick", &[U1]),
    (0x16, "DW_OP_swap", &[]),
    (0x17, "DW_OP_rot", &[]),
    (0x18, "DW_OP_xderef", &[]),
    (0x19, "DW_OP_abs", &[]),
    (0x1a, "DW_OP_and", &[]),
    (0x1b, "DW_OP_div", &[]),
    (0x1c, "DW_OP_minus", &[]),
    (0x1d, "DW_OP_mod", &[]),
    (0x1e, "DW_OP_mul", &[]),
    (0x1f, "DW_OP_neg", &[]),
    (0x20, "DW_OP_not", &[]),
    (0x21, "DW_OP_or", &[]),
    (0x22, "DW_OP_plus", &[]),
    (0x23, "DW_OP_plus_uconst", &[Uleb]),
    (0x24, "DW_OP_shl", &[]),
    (0x25, "DW_OP_shr", &[]),
    (0x26, "DW_OP_shra", &[]),
    (0x27, "DW_OP_xor", &[]),
    (0x28, "DW_OP_bra", &[S2]),
    (0x29, "DW_OP_eq", &[]),
    (0x2a, "DW_OP_ge", &[]),
    (0x2b, "DW_OP_gt", &[]),
    (0x2c, "DW_OP_le", &[]),
    (0x2d, "DW_OP_lt", &[]),
    (0x2e, "DW_OP_ne", &[]),
    (0x2f, "DW_OP_skip", &[S2]),
    (0x90, "DW_OP_regx", &[Uleb]),
    (0x91, "DW_OP_fbreg", &[Sleb]),
    (0x92, "DW_OP_bregx", &[Uleb, Sleb]),
    (0x93, "DW_OP_piece", &[Uleb]),
    (0x94, "DW_OP_deref_size", &[U1]),
    (0x95, "DW_OP_xderef_size", &[U1]),
    (0x96, "DW_OP_nop", &[]),
    (0x97, "DW_OP_push_object_address", &[]),
    (0x98, "DW_OP_call2", &[U2]),
    (0x99, "DW_OP_call4", &[U4]),
    (0x9a, "DW_OP_call_ref", &[Int]),
    (0x9b, "DW_OP_form_tls_address", &[]),
    (0x9c, "DW_OP_call_frame_cfa", &[]),
    (0x9d, "DW_OP_bit_piece", &[Uleb, Uleb]),
    (0x9e, "DW_OP_implicit_value", &[Uleb, Blob]),
    (0x9f, "DW_OP_stack_value", &[]),
    (0xa0, "DW_OP_implicit_pointer", &[Int, Sleb]),
    (0xa1, "DW_OP_addrx", &[Uleb]),
    (0xa2, "DW_OP_constx", &[Uleb]),
    (0xa3, "DW_OP_entry_value", &[Uleb, Blob]),
    (0xa4, "DW_OP_const_type", &[Uleb, U1, Blob]),
    (0xa5, "DW_OP_regval_type", &[Uleb, Uleb]),
    (0xa6, "DW_OP_deref_type", &[U1, Uleb]),
    (0xa7, "DW_OP_xderef_type", &[U1, Uleb]),
    (0xa8, "DW_OP_convert", &[Uleb]),
    (0xa9, "DW_OP_reinterpret", &[Uleb]),
];

/// x86-64.dwarf's register mappings for DWARF registers 0-31 (the ones `toString` names)
const REGS: [&str; 32] = [
    "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    "RIP", "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7", "XMM8", "XMM9", "XMM10", "XMM11", "XMM12",
    "XMM13", "XMM14",
];

/// Whether x86-64.dwarf maps a DWARF register (`getGhidraReg` not null)
fn mapped(r: u64) -> bool {
    r <= 55 || (62..=64).contains(&r)
}

struct Instr {
    op: u8,
    name: String,
    types: &'static [T],
    vals: Vec<i64>,
    blob: Vec<u8>,
    offset: usize,
}

/// A read expression (`DWARFExpression`)
pub struct Expr(Vec<Instr>);

/// Why reading or evaluating failed (`DWARFExpressionException` and its subclasses)
#[derive(Debug)]
pub enum Fail {
    /// `DWARFExpressionValueException`: a register's value was asked for
    Value,
    /// `DWARFExpressionTerminalDerefException`: a `DW_OP_deref` as the last operation
    Deref(Vn),
    /// any other `DWARFExpressionException`
    Other,
    /// what the port does not know the result of
    Unported(&'static str),
}

/// The address space of a varnode the evaluator gives
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Space {
    Stack,
    Register,
    Ram,
}

/// A varnode: its space and offset (the size is not needed here)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vn {
    pub space: Space,
    pub offset: i64,
}

#[derive(Clone, Copy)]
enum V {
    /// a `Scalar`; every one the evaluator makes here is of the pointer size (64 bits)
    S(i64),
    N(Vn),
}

impl Expr {
    /// `DWARFExpression.read`; an unknown opcode or a short read is `Fail::Other`
    pub fn read(bytes: &[u8], addr_size: u8, int_size: u8) -> Result<Expr, Fail> {
        let mut c = Cursor::new(bytes, 0);
        let mut out = Vec::new();
        while c.p < bytes.len() {
            let offset = c.p;
            let op = c.u8().map_err(|_| Fail::Other)?;
            let (name, types): (String, &'static [T]) = match op {
                0x30..=0x4f => (format!("DW_OP_lit{}", op - 0x30), &[]),
                0x50..=0x6f => (format!("DW_OP_reg{}", op - 0x50), &[]),
                0x70..=0x8f => (format!("DW_OP_breg{}", op - 0x70), &[Sleb]),
                _ => match OPS.iter().find(|o| o.0 == op) {
                    Some(o) => (o.1.to_string(), o.2),
                    // DW_OP_unknown_opcode: "Unknown DWARF opcode(s) encountered"
                    None => return Err(Fail::Other),
                },
            };
            let mut vals = vec![0i64; types.len()];
            let mut blob = Vec::new();
            for (i, t) in types.iter().enumerate() {
                let r = match t {
                    Addr => c.uint(addr_size as usize).map(|v| v as i64),
                    S1 => c.uint(1).map(|v| v as u8 as i8 as i64),
                    S2 => c.uint(2).map(|v| v as u16 as i16 as i64),
                    S4 => c.uint(4).map(|v| v as u32 as i32 as i64),
                    S8 | U8 => c.uint(8).map(|v| v as i64),
                    U1 => c.uint(1).map(|v| v as i64),
                    U2 => c.uint(2).map(|v| v as i64),
                    U4 => c.uint(4).map(|v| v as i64),
                    Sleb => c.sleb(),
                    Uleb => c.uleb().map(|v| v as i64),
                    Int => c.uint(int_size as usize).map(|v| v as i64),
                    Blob => {
                        let n = usize::try_from(vals[i - 1]).unwrap_or(usize::MAX);
                        if c.p.checked_add(n).is_none_or(|e| e > bytes.len()) {
                            return Err(Fail::Other);
                        }
                        blob = bytes[c.p..c.p + n].to_vec();
                        c.p += n;
                        Ok(0)
                    }
                };
                vals[i] = r.map_err(|_| Fail::Other)?;
            }
            out.push(Instr { op, name, types, vals, blob, offset });
        }
        Ok(Expr(out))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `toString(cu)`: the operations by `; `, a register operation with its register's name,
    /// the operands after `:`
    pub fn text(&self) -> String {
        let mut s = String::new();
        for (k, ins) in self.0.iter().enumerate() {
            if k != 0 {
                s.push_str("; ");
            }
            s.push_str(&ins.name);
            if let 0x50..=0x8f = ins.op {
                s.push_str(&format!("({})", REGS[((ins.op - 0x50) % 0x20) as usize]));
            }
            for (i, t) in ins.types.iter().enumerate() {
                if i == 0 {
                    s.push(':');
                }
                s.push(' ');
                let v = ins.vals[i];
                match t {
                    Addr => s.push_str(&format!("{v:x}")),
                    S1 | S2 | S4 | S8 | Sleb => s.push_str(&format!("{}{v}", if v > 0 { "+" } else { "" })),
                    U1 | U2 | U4 | U8 | Uleb | Int => s.push_str(&(v as u64).to_string()),
                    // NumericUtilities.convertBytesToString(blob, " ")
                    Blob => s.push_str(&ins.blob.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")),
                }
            }
            if ins.op == 0x28 || ins.op == 0x2f {
                let dest = ins.offset as i64 + ins.vals[0];
                let idx = self.find(dest).map_or(-1, |i| i as i64);
                s.push_str(&format!(" /* dest index: {idx}, offset: {:03x} */", dest as i32));
            }
        }
        s
    }

    fn find(&self, offset: i64) -> Option<usize> {
        self.0.iter().position(|i| i.offset as i64 == offset)
    }

    /// `evaluate` then `popVarnode`. `frame_base`: the function's frame base at the variable's
    /// start (`setFrameBaseVal`); `fixup`: what `getDataAddress` adds to an address.
    pub fn eval(&self, frame_base: Option<Vn>, fixup: u64) -> Result<Vn, Fail> {
        let mut st: Vec<V> = Vec::new();
        // the value reader: RBP is the stack at -8; any other register's value is not known
        let reg_val = |r: u64| if r == 6 { Ok(Vn { space: Space::Stack, offset: -8 }) } else { Err(Fail::Value) };
        let pop = |st: &mut Vec<V>| st.pop().ok_or(Fail::Other);
        // stackValueToScalar: a register is read (its value is a varnode, not a scalar)
        let scalar = |v: V| match v {
            V::S(s) => Ok(s),
            V::N(n) if n.space == Space::Register => Err(Fail::Value),
            V::N(_) => Err(Fail::Other),
        };
        let pop_vn = |st: &mut Vec<V>| match pop(st)? {
            V::S(s) => Ok(Vn { space: Space::Ram, offset: s }),
            V::N(n) => Ok(n),
        };
        let (mut i, mut steps) = (0usize, 0);
        while i < self.0.len() {
            if steps >= 1000 {
                return Err(Fail::Other);
            }
            let ins = &self.0[i];
            let a = ins.vals.first().copied().unwrap_or(0);
            match ins.op {
                0x30..=0x4f => st.push(V::S(i64::from(ins.op - 0x30))),
                0x70..=0x8f => {
                    let v = reg_val(u64::from(ins.op - 0x70))?;
                    st.push(V::N(Vn { space: v.space, offset: v.offset.wrapping_add(a) }));
                }
                0x50..=0x6f => st.push(V::N(reg_val(u64::from(ins.op - 0x50))?)),
                0x03 => st.push(V::N(Vn { space: Space::Ram, offset: a.wrapping_add(fixup as i64) })),
                0x08..=0x11 => st.push(V::S(a)),
                0x90 => {
                    if !mapped(a as u64) {
                        return Err(Fail::Other);
                    }
                    st.push(V::N(Vn { space: Space::Register, offset: a }));
                }
                0x91 => {
                    let fb = frame_base.ok_or(Fail::Other)?;
                    let v = V::N(Vn { space: fb.space, offset: fb.offset.wrapping_add(a) });
                    // no `break` after DW_OP_fbreg: it goes on into DW_OP_dup
                    st.push(v);
                    st.push(v);
                }
                0x12 => {
                    let v = *st.last().ok_or(Fail::Other)?;
                    st.push(v);
                }
                0x13 => {
                    pop(&mut st)?;
                }
                0x15 => {
                    let k = a as usize;
                    if k >= st.len() {
                        return Err(Fail::Other);
                    }
                    st.push(st[st.len() - k - 1]);
                }
                0x14 => {
                    if st.len() < 2 {
                        return Err(Fail::Other);
                    }
                    st.push(st[st.len() - 2]);
                }
                0x16 => {
                    let (x, y) = (pop(&mut st)?, pop(&mut st)?);
                    st.push(x);
                    st.push(y);
                }
                0x17 => {
                    let (x, y, z) = (pop(&mut st)?, pop(&mut st)?, pop(&mut st)?);
                    st.push(x);
                    st.push(z);
                    st.push(y);
                }
                0x06 => {
                    if i == self.0.len() - 1 {
                        return Err(Fail::Deref(pop_vn(&mut st)?));
                    }
                    return Err(Fail::Other);
                }
                0x9c => st.push(V::N(Vn { space: Space::Stack, offset: 8 })),
                0x19 | 0x1f | 0x20 | 0x23 => {
                    let x = scalar(pop(&mut st)?)?;
                    st.push(V::S(match ins.op {
                        0x19 => x.wrapping_abs(),
                        0x1f => x.wrapping_neg(),
                        0x20 => !x,
                        _ => x.wrapping_add(a),
                    }));
                }
                0x1a..=0x1e | 0x21 | 0x22 | 0x24..=0x27 | 0x29..=0x2e => {
                    let x = scalar(pop(&mut st)?)?;
                    let y = scalar(pop(&mut st)?)?;
                    if matches!(ins.op, 0x1b | 0x1d) && x == 0 {
                        return Err(Fail::Other);
                    }
                    st.push(V::S(match ins.op {
                        0x1a => x & y,
                        0x1b => y.wrapping_div(x),
                        0x1c => y.wrapping_sub(x),
                        0x1d => y.wrapping_rem(x),
                        0x1e => y.wrapping_mul(x),
                        0x21 => y | x,
                        0x22 => y.wrapping_add(x),
                        // Java's shifts take the count modulo 64
                        0x24 => y.wrapping_shl(x as u32),
                        0x25 => ((y as u64).wrapping_shr(x as u32)) as i64,
                        0x26 => y.wrapping_shr(x as u32),
                        0x27 => y ^ x,
                        0x29 => i64::from(y == x),
                        0x2a => i64::from(y >= x),
                        0x2b => i64::from(y > x),
                        0x2c => i64::from(y <= x),
                        0x2d => i64::from(y < x),
                        _ => i64::from(y != x),
                    }));
                }
                0x2f | 0x28 => {
                    let take = ins.op == 0x2f || scalar(pop(&mut st)?)? != 0;
                    if take {
                        let dest = ins.offset as i64 + a;
                        i = self.find(dest).ok_or(Fail::Other)?;
                        steps += 1;
                        continue;
                    }
                }
                0x96 => {}
                0xa1 | 0xa2 => return Err(Fail::Unported("DW_OP_addrx / DW_OP_constx (DWARF 5)")),
                _ => return Err(Fail::Other),
            }
            i += 1;
            steps += 1;
        }
        pop_vn(&mut st)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations() {
        let cfa = Vn { space: Space::Stack, offset: 8 };
        // DW_OP_fbreg -20 with the CFA as the frame base: a local of the stack frame
        let e = Expr::read(&[0x91, 0x6c], 8, 4).unwrap();
        assert_eq!(e.eval(Some(cfa), 0).unwrap(), Vn { space: Space::Stack, offset: -12 });
        assert!(matches!(e.eval(None, 0), Err(Fail::Other)));
        // DW_OP_reg5: RDI's value is not known; the text Java's comment has
        let e = Expr::read(&[0x55], 8, 4).unwrap();
        assert!(matches!(e.eval(None, 0), Err(Fail::Value)));
        assert_eq!(e.text(), "DW_OP_reg5(RDI)");
        let e = Expr::read(&[0x74, 0x00, 0x93, 0x04, 0x74, 0xe0, 0x00], 8, 4).unwrap();
        assert_eq!(e.text(), "DW_OP_breg4(RSI): 0; DW_OP_piece: 4; DW_OP_breg4(RSI): +96");
        // DW_OP_breg6 (RBP) 16: the stack at 8
        let e = Expr::read(&[0x76, 0x10], 8, 4).unwrap();
        assert_eq!(e.eval(None, 0).unwrap(), Vn { space: Space::Stack, offset: 8 });
        // an unknown opcode
        assert!(matches!(Expr::read(&[0xf3, 0x01, 0x55], 8, 4), Err(Fail::Other)));
    }
}
