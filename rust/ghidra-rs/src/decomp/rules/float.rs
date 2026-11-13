//! Constant folding of the float ops through `FloatFormat` (float.cc), IEEE single and double.

use super::*;

/// The float ops (`TypeOpFloat*`), folded through `FloatFormat` (IEEE single and double).
pub(super) fn is_float(opc: Opcode) -> bool {
    matches!(
        opc,
        FloatEqual
            | FloatNotequal
            | FloatLess
            | FloatLessequal
            | FloatNan
            | FloatAdd
            | FloatDiv
            | FloatMult
            | FloatSub
            | FloatNeg
            | FloatAbs
            | FloatSqrt
            | FloatInt2float
            | FloatFloat2float
            | FloatTrunc
            | FloatCeil
            | FloatFloor
            | FloatRound
    )
}

/// `FloatFormat::getHostFloat`: a NaN becomes the host's quiet NaN with the encoding's sign
/// (the payload is dropped).
pub(super) fn host_float(size: u32, enc: u64) -> Option<f64> {
    let v = match size {
        4 => f64::from(f32::from_bits(enc as u32)),
        8 => f64::from_bits(enc),
        _ => return None,
    };
    Some(if v.is_nan() { f64::NAN.copysign(v) } else { v })
}

/// `FloatFormat::getEncoding` (a double rounds to the nearest single); a NaN is encoded as
/// `getNaNEncoding` does: the sign, every exponent bit and only the top fraction bit.
pub(super) fn float_encoding(size: u32, val: f64) -> Option<u64> {
    let neg = u64::from(val.is_sign_negative());
    match size {
        4 if val.is_nan() => Some(neg << 31 | 0x7fc0_0000),
        8 if val.is_nan() => Some(neg << 63 | 0x7ff8_0000_0000_0000),
        4 => Some(u64::from((val as f32).to_bits())),
        8 => Some(val.to_bits()),
        _ => None,
    }
}

/// `FloatFormat::opTrunc`'s `(intb)val` as x86 `cvttsd2si` computes it: a NaN or a value out of
/// the 64-bit range gives `0x8000000000000000`.
fn trunc_i64(v: f64) -> i64 {
    if v.is_nan() || !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&v) {
        i64::MIN
    } else {
        v as i64
    }
}

/// `evaluateUnary`/`evaluateBinary` of the float ops on constants; `None` where the C++
/// has no float format for the size.
pub(super) fn eval_float(fd: &Funcdata, op: OpId) -> Option<u64> {
    let o = fd.op(op);
    let sout = fd.vn(o.out?).size;
    let a = fd.vn(*o.ins.first()?);
    let (sin, x) = (a.size, a.offset);
    let fa = || host_float(sin, x);
    let fb = || o.ins.get(1).and_then(|&b| host_float(sin, fd.vn(b).offset));
    let cmp = |f: fn(f64, f64) -> bool| Some(u64::from(f(fa()?, fb()?)));
    let enc = |v: f64| float_encoding(sout, v);
    match o.opc {
        FloatEqual => cmp(|p, q| p == q),
        FloatNotequal => cmp(|p, q| p != q),
        FloatLess => cmp(|p, q| p < q),
        FloatLessequal => cmp(|p, q| p <= q),
        FloatNan => Some(u64::from(fa()?.is_nan())),
        FloatAdd => enc(fa()? + fb()?),
        FloatSub => enc(fa()? - fb()?),
        FloatMult => enc(fa()? * fb()?),
        FloatDiv => enc(fa()? / fb()?),
        FloatNeg => enc(-fa()?),
        FloatAbs => enc(fa()?.abs()),
        FloatSqrt => enc(fa()?.sqrt()),
        FloatCeil => enc(fa()?.ceil()),
        FloatFloor => enc(fa()?.floor()),
        FloatRound => enc(fa()?.round()),
        FloatFloat2float => enc(fa()?),
        FloatInt2float => {
            let sh = 64 - 8 * sin.min(8);
            enc((((x << sh) as i64) >> sh) as f64)
        }
        FloatTrunc => Some((trunc_i64(fa()?) as u64) & calc_mask(sout)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nan_and_trunc_follow_float_format() {
        // FLOAT_NEG of a NaN with a payload: the quiet NaN, sign flipped, payload dropped
        let neg = float_encoding(4, -host_float(4, 0x7fc0_0001).unwrap()).unwrap();
        assert_eq!(neg, 0xffc0_0000);
        assert_eq!(trunc_i64(f64::NAN), i64::MIN);
        assert_eq!(trunc_i64(1e300), i64::MIN);
        assert_eq!(trunc_i64(-3.7), -3);
    }
}
