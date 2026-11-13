//! P-code opcodes (port of `opcodes.hh`) and the per-opcode facts the early stages need: the
//! operator names `print raw` uses (from the `TypeOp` constructors in `typeop.cc`) and the
//! branch/call classes of `PcodeOp::flags`.

/// Port of `enum OpCode` (opcodes.hh); the discriminants are Ghidra's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum Opcode {
    Copy = 1,
    Load,
    Store,
    Branch,
    Cbranch,
    Branchind,
    Call,
    Callind,
    Callother,
    Return,
    IntEqual,
    IntNotequal,
    IntSless,
    IntSlessequal,
    IntLess,
    IntLessequal,
    IntZext,
    IntSext,
    IntAdd,
    IntSub,
    IntCarry,
    IntScarry,
    IntSborrow,
    Int2comp,
    IntNegate,
    IntXor,
    IntAnd,
    IntOr,
    IntLeft,
    IntRight,
    IntSright,
    IntMult,
    IntDiv,
    IntSdiv,
    IntRem,
    IntSrem,
    BoolNegate,
    BoolXor,
    BoolAnd,
    BoolOr,
    FloatEqual,
    FloatNotequal,
    FloatLess,
    FloatLessequal,
    Unused1,
    FloatNan,
    FloatAdd,
    FloatDiv,
    FloatMult,
    FloatSub,
    FloatNeg,
    FloatAbs,
    FloatSqrt,
    FloatInt2float,
    FloatFloat2float,
    FloatTrunc,
    FloatCeil,
    FloatFloor,
    FloatRound,
    Multiequal,
    Indirect,
    Piece,
    Subpiece,
    Cast,
    Ptradd,
    Ptrsub,
    Segmentop,
    Cpoolref,
    New,
    Insert,
    Zpull,
    Popcount,
    Lzcount,
    Spull,
}

/// How `print raw` lays an op out (the `TypeOp` subclass whose `printRaw` it uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawForm {
    /// `out = in0 <name> in1` (TypeOpBinary)
    Binary(&'static str),
    /// `out = <name> in0` (TypeOpUnary)
    Unary(&'static str),
    /// `out = <name>(in0,in1,...)` (TypeOpFunc); [`Sizes`] says which operand sizes the name gets
    Func(&'static str, Sizes),
    /// an op with its own printRaw
    Special,
}

/// Which sizes `getOperatorName` appends to a function-style name (`ZEXT14`, `CARRY4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sizes {
    None,
    In0,
    In0Out,
    In0In1,
}

impl Opcode {
    /// The opcode with Ghidra's number `n`, as the SLEIGH engine emits it.
    pub(crate) fn from_u8(n: u8) -> Option<Opcode> {
        use Opcode::*;
        const ALL: [Opcode; 74] = [
            Copy,
            Load,
            Store,
            Branch,
            Cbranch,
            Branchind,
            Call,
            Callind,
            Callother,
            Return,
            IntEqual,
            IntNotequal,
            IntSless,
            IntSlessequal,
            IntLess,
            IntLessequal,
            IntZext,
            IntSext,
            IntAdd,
            IntSub,
            IntCarry,
            IntScarry,
            IntSborrow,
            Int2comp,
            IntNegate,
            IntXor,
            IntAnd,
            IntOr,
            IntLeft,
            IntRight,
            IntSright,
            IntMult,
            IntDiv,
            IntSdiv,
            IntRem,
            IntSrem,
            BoolNegate,
            BoolXor,
            BoolAnd,
            BoolOr,
            FloatEqual,
            FloatNotequal,
            FloatLess,
            FloatLessequal,
            Unused1,
            FloatNan,
            FloatAdd,
            FloatDiv,
            FloatMult,
            FloatSub,
            FloatNeg,
            FloatAbs,
            FloatSqrt,
            FloatInt2float,
            FloatFloat2float,
            FloatTrunc,
            FloatCeil,
            FloatFloor,
            FloatRound,
            Multiequal,
            Indirect,
            Piece,
            Subpiece,
            Cast,
            Ptradd,
            Ptrsub,
            Segmentop,
            Cpoolref,
            New,
            Insert,
            Zpull,
            Popcount,
            Lzcount,
            Spull,
        ];
        ALL.get(usize::from(n).checked_sub(1)?).copied()
    }

    /// `PcodeOp::isBranch`: BRANCH, CBRANCH and BRANCHIND carry the `branch` flag.
    pub(crate) fn is_branch(self) -> bool {
        matches!(self, Opcode::Branch | Opcode::Cbranch | Opcode::Branchind)
    }

    /// The `print raw` layout and operator name, from the TypeOp constructors (typeop.cc).
    pub(crate) fn raw_form(self) -> RawForm {
        use Opcode::*;
        use RawForm::*;
        match self {
            IntEqual | FloatEqual => Binary(if self == IntEqual { "==" } else { "f==" }),
            IntNotequal => Binary("!="),
            // TypeOpPtrsub::printRaw (ActionConstantPtr, stage S6)
            Ptrsub => Binary("->"),
            FloatNotequal => Binary("f!="),
            IntSless => Binary("s<"),
            IntSlessequal => Binary("s<="),
            IntLess => Binary("<"),
            IntLessequal => Binary("<="),
            FloatLess => Binary("f<"),
            FloatLessequal => Binary("f<="),
            IntAdd => Binary("+"),
            IntSub => Binary("-"),
            IntXor => Binary("^"),
            IntAnd => Binary("&"),
            IntOr => Binary("|"),
            IntLeft => Binary("<<"),
            IntRight => Binary(">>"),
            IntSright => Binary("s>>"),
            IntMult => Binary("*"),
            IntDiv => Binary("/"),
            IntSdiv => Binary("s/"),
            IntRem => Binary("%"),
            IntSrem => Binary("s%"),
            BoolXor => Binary("^^"),
            BoolAnd => Binary("&&"),
            BoolOr => Binary("||"),
            FloatAdd => Binary("f+"),
            FloatDiv => Binary("f/"),
            FloatMult => Binary("f*"),
            FloatSub => Binary("f-"),
            Int2comp => Unary("-"),
            IntNegate => Unary("~"),
            BoolNegate => Unary("!"),
            FloatNeg => Unary("f-"),
            IntZext => Func("ZEXT", Sizes::In0Out),
            IntSext => Func("SEXT", Sizes::In0Out),
            IntCarry => Func("CARRY", Sizes::In0),
            IntScarry => Func("SCARRY", Sizes::In0),
            IntSborrow => Func("SBORROW", Sizes::In0),
            Piece => Func("CONCAT", Sizes::In0In1),
            Subpiece => Func("SUB", Sizes::In0Out),
            FloatNan => Func("NAN", Sizes::None),
            FloatAbs => Func("ABS", Sizes::None),
            FloatSqrt => Func("SQRT", Sizes::None),
            FloatInt2float => Func("INT2FLOAT", Sizes::None),
            FloatFloat2float => Func("FLOAT2FLOAT", Sizes::None),
            FloatTrunc => Func("TRUNC", Sizes::None),
            FloatCeil => Func("CEIL", Sizes::None),
            FloatFloor => Func("FLOOR", Sizes::None),
            FloatRound => Func("ROUND", Sizes::None),
            Insert => Func("INSERT", Sizes::None),
            Zpull => Func("ZPULL", Sizes::None),
            Spull => Func("SPULL", Sizes::None),
            Popcount => Func("POPCOUNT", Sizes::None),
            Lzcount => Func("LZCOUNT", Sizes::None),
            _ => Special,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_match_ghidra() {
        assert_eq!(Opcode::from_u8(1), Some(Opcode::Copy));
        assert_eq!(Opcode::from_u8(10), Some(Opcode::Return));
        assert_eq!(Opcode::from_u8(60), Some(Opcode::Multiequal));
        assert_eq!(Opcode::from_u8(74), Some(Opcode::Spull));
        assert_eq!(Opcode::from_u8(0), None);
        assert_eq!(Opcode::Lzcount as u8, 73);
    }
}
