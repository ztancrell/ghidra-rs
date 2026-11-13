//! The rule pool walk: port of `ActionPool` (`addRule`, `apply`, `processOp`, action.cc), and
//! the main loop's `ActionNonzeroMask`.

use super::*;

/// An `ActionPool`'s rules by opcode (`perop`), in the order they were added.
#[derive(Debug, Clone, Default)]
pub(crate) struct Pool {
    perop: Vec<Vec<&'static Rule>>,
}

impl Pool {
    fn for_opc(&self, opc: Opcode) -> &[&'static Rule] {
        self.perop.get(opc as usize).map_or(&[], |v| v.as_slice())
    }
}

/// The rules of `pool` the action keeps (its groups on, not switched off by `togglerule`),
/// filed by opcode once (`ActionPool::addRule`).
pub(crate) fn select(pool: &'static [Rule], on: impl Fn(&Rule) -> bool) -> Pool {
    let mut perop: Vec<Vec<&'static Rule>> = Vec::new();
    for rl in pool.iter().filter(|rl| on(rl)) {
        for &opc in rl.ops {
            let i = opc as usize;
            if perop.len() <= i {
                perop.resize(i + 1, Vec::new());
            }
            perop[i].push(rl);
        }
    }
    Pool { perop }
}

/// Port of `ActionPool::apply`: every op in sequence-number order (ops made on the way are
/// visited when they sort after the current one), the dead ones freed (`opDeadAndGone`).
pub(crate) fn pool_apply(fd: &mut Funcdata, arch: &Arch, pool: &Pool) -> Result<i32> {
    let mut count = 0;
    let mut cur = fd.op_after(None);
    while let Some(op) = cur {
        let seq = fd.op(op).seq;
        if fd.op(op).is_dead() {
            fd.op_dead_and_gone(op);
        } else {
            count += process_op(fd, arch, pool, op)?;
        }
        cur = fd.op_after(Some(seq));
    }
    Ok(count)
}

/// Port of `ActionPool::processOp`: the rules for the op's opcode in order, from the first
/// again when one changes the opcode.
fn process_op(fd: &mut Funcdata, arch: &Arch, pool: &Pool, op: OpId) -> Result<i32> {
    let mut count = 0;
    let mut opc = fd.op(op).opc;
    let mut i = 0;
    while let Some(&rl) = pool.for_opc(opc).get(i) {
        i += 1;
        let res = (rl.apply)(fd, op, arch)?;
        if res > 0 {
            count += res;
            if fd.op(op).is_dead() {
                break;
            }
            if opc != fd.op(op).opc {
                opc = fd.op(op).opc;
                i = 0;
            }
        }
    }
    Ok(count)
}

/// Port of `ActionNonzeroMask::apply` (`Funcdata::calcNZMask`).
pub(crate) fn nonzero_mask(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    crate::decomp::jumptable::calc_nz_mask_unfolded(fd, arch);
    Ok(0)
}
