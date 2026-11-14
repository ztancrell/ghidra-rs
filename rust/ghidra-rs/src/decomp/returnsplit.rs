//! Port of `ActionReturnSplit` (blockaction.cc) with `Funcdata::nodeSplit` and
//! `CloneBlockOps` (funcdata_block.cc), and the structure queries it needs: `BlockGoto::
//! gotoPrints` and `nextFlowAfter` of each block kind. A RETURN block reached by unstructured
//! gotos gets a copy for each goto edge, so the gotos become plain returns.

use std::collections::HashMap;

use super::block::BlockId;
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::structure::{Kind, SId, Structure};
use super::varnode::{VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, Result};

/// `ActionReturnSplit::apply`: for each RETURN (in the RETURN op list's order) whose block is
/// splittable and is the target of gotos, the in-edges arriving through those gotos are split
/// off, one new block each, after all the RETURNs are examined.
pub(crate) fn return_split(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    if fd.structure.is_empty() {
        return Ok(0);
    }
    let splits = {
        let s = std::mem::take(&mut fd.structure);
        let res = find_splits(fd, &s);
        fd.structure = s;
        res?
    };
    for &(parent, edge) in &splits {
        node_split(fd, parent, edge)?;
    }
    Ok(splits.len() as i32)
}

/// The (return block, in-edge) pairs to split, in the order `apply` collects them.
fn find_splits(fd: &Funcdata, s: &Structure) -> Result<Vec<(BlockId, usize)>> {
    let copies: HashMap<BlockId, SId> = (0..s.blocks.len() as u32)
        .map(SId)
        .filter_map(|b| match s.b(b).kind {
            Kind::Copy(bb) => Some((bb, b)),
            _ => None,
        })
        .collect();
    let copy = |bb: BlockId| copies.get(&bb).copied();
    // data.beginOp(CPUI_RETURN): the RETURN op list in its order
    let returns = fd.ops_created_with(Opcode::Return);
    let mut marks: Vec<SId> = Vec::new();
    let mut res = Vec::new();
    for op in returns {
        let Some(parent) = fd.op(op).parent else { continue };
        let ins = &fd.blocks.block(parent).ins;
        if ins.len() <= 1 || !is_splittable(fd, parent) {
            continue;
        }
        // gatherReturnGotos: the goto and if-goto blocks over a predecessor whose goto reaches parent
        let mut gotoblocks = Vec::new();
        for e in ins {
            let mut bl = copy(e.point);
            while let Some(b) = bl {
                if !gotoblocks.contains(&b) && goto_target_leaf(s, b)? == Some(parent) {
                    gotoblocks.push(b);
                }
                bl = s.b(b).parent;
            }
        }
        if gotoblocks.is_empty() {
            continue;
        }
        marks.clone_from(&gotoblocks);
        let mut splitcount = 0;
        for i in (0..ins.len()).rev() {
            let mut bl = copy(ins[i].point);
            while let Some(b) = bl {
                if marks.contains(&b) {
                    res.push((parent, i));
                    splitcount += 1;
                    break;
                }
                bl = s.b(b).parent;
            }
        }
        // not every in-edge may be split
        if ins.len() == splitcount {
            res.pop();
        }
    }
    Ok(res)
}

/// The basic block a goto or if-goto block's printed goto reaches (`gotoPrints` for a plain
/// goto), followed down component 0 (`subBlock(0)` to the basic block).
fn goto_target_leaf(s: &Structure, b: SId) -> Result<Option<BlockId>> {
    let target = match s.b(b).kind {
        Kind::Goto(t) if goto_prints(s, b, t) => t,
        Kind::IfGoto(t) => t,
        _ => return Ok(None),
    };
    let mut ret = target;
    loop {
        match s.b(ret).kind {
            Kind::Copy(bb) => return Ok(Some(bb)),
            _ => match s.b(ret).list.first() {
                Some(&c) => ret = c,
                None => return err("goto target without a basic block"),
            },
        }
    }
}

/// `getFrontLeaf` as a structure block (the copy reached through component 0).
fn front_leaf(s: &Structure, mut b: SId) -> Option<SId> {
    loop {
        match s.b(b).kind {
            Kind::Copy(_) => return Some(b),
            _ => b = *s.b(b).list.first()?,
        }
    }
}

/// `BlockGoto::gotoPrints`: the goto prints unless the flow after it reaches its target anyway.
fn goto_prints(s: &Structure, b: SId, target: SId) -> bool {
    match s.b(b).parent {
        Some(p) => front_leaf(s, target) != next_flow_after(s, p, b),
        None => false,
    }
}

/// `nextFlowAfter(bl)` of `p` (the leaf executing after its component `bl`), going up the
/// parents where the C++ recurses.
fn next_flow_after(s: &Structure, mut p: SId, mut bl: SId) -> Option<SId> {
    loop {
        let pb = s.b(p);
        let up = |pb: &super::structure::SBlock| pb.parent;
        match &pb.kind {
            Kind::Goto(t) => return front_leaf(s, *t),
            Kind::MultiGoto { .. } | Kind::Condition(_) | Kind::DoWhile => return None,
            Kind::If | Kind::IfElse | Kind::IfNoExit | Kind::IfGoto(_) => {
                if pb.list.first() == Some(&bl) {
                    return None;
                }
            }
            Kind::WhileDo => {
                return if pb.list.first() == Some(&bl) { None } else { front_leaf(s, *pb.list.first()?) };
            }
            Kind::InfLoop => return front_leaf(s, *pb.list.first()?),
            Kind::Switch => {
                if pb.list.first() == Some(&bl) || !matches!(s.b(bl).kind, Kind::Goto(_)) {
                    return None;
                }
                // the case blocks in `grabCaseBasic` order: the components, then the goto edges
                let mut cases: Vec<SId> = pb.list[1..].to_vec();
                if let Kind::MultiGoto { gotos, .. } = &s.b(pb.list[0]).kind {
                    cases.extend(gotos);
                }
                let i = cases.iter().position(|&c| c == bl)?;
                if let Some(&next) = cases.get(i + 1) {
                    return front_leaf(s, next);
                }
            }
            Kind::Graph | Kind::List => {
                let i = pb.list.iter().position(|&c| c == bl)?;
                if let Some(&next) = pb.list.get(i + 1) {
                    return front_leaf(s, next);
                }
            }
            Kind::Copy(_) => return None,
        }
        bl = p;
        p = up(pb)?;
    }
}

/// `ActionReturnSplit::isSplittable`: only MULTIEQUALs, and COPYs and the RETURN reading no
/// free varnode.
fn is_splittable(fd: &Funcdata, b: BlockId) -> bool {
    fd.blocks.block(b).ops.iter().all(|&op| {
        let o = fd.op(op);
        match o.opc {
            Opcode::Multiequal => true,
            Opcode::Copy | Opcode::Return => o.ins.iter().all(|&v| {
                let vn = fd.vn(v);
                vn.is_constant() || vn.is_annotation() || !vn.is_free()
            }),
            _ => false,
        }
    })
}

/// `Funcdata::nodeSplit` with `nodeSplitBlockEdge` and `CloneBlockOps::cloneBlock`: in-edge
/// `inedge` of `b` (which has no out-edges) goes to a new copy of `b`. (`nodeSplit`'s check for
/// redundant in-edges marks `b` itself, so it can only fire on a self loop, which a block
/// without out-edges cannot have; `f_duplicate_block` is not kept, only printing reads it.)
fn node_split(fd: &mut Funcdata, b: BlockId, inedge: usize) -> Result<()> {
    let bl = fd.blocks.block(b);
    if !bl.outs.is_empty() {
        return err("Cannot (currently) nodesplit block with out flow");
    }
    if bl.ins.len() <= 1 {
        return err("Cannot nodesplit block with only 1 in edge");
    }
    let (a, start, stop) = (bl.ins[inedge].point, bl.start, bl.stop);
    let bprime = fd.blocks.new_block(start);
    fd.blocks.block_mut(bprime).stop = stop;
    fd.blocks.switch_edge(a, b, bprime);
    clone_block(fd, b, bprime, inedge)?;
    super::coreaction::structure_reset(fd)
}

/// `CloneBlockOps::cloneBlock`: each op of `b` but a BRANCH is cloned (flags and output) at the
/// end of `bprime`, then `patchInputs`.
fn clone_block(fd: &mut Funcdata, b: BlockId, bprime: BlockId, inedge: usize) -> Result<()> {
    // the bits `buildOpClone` (funcdata_block.cc) keeps that ghidra-rs models (the halt kind is
    // copied below; `nocollapse`, `no_indirect_collapse`, `ptrflow` and the additional flags
    // other than `special_print` are not modelled)
    const OP_KEEP: [OpFlags; 8] = [
        OpFlags::START_BASIC,
        OpFlags::START_INSTRUCTION,
        OpFlags::INDIRECT_CREATION,
        OpFlags::INDIRECT_STORE,
        OpFlags::CALCULATED_BOOL,
        OpFlags::STOP_TYPE_PROPAGATION,
        OpFlags::NONPRINTING,
        OpFlags::SPECIAL_PRINT,
    ];
    const VN_KEEP: [VnFlags; 7] = [
        VnFlags::INCIDENTAL_COPY,
        VnFlags::PERSIST,
        VnFlags::ADDRTIED,
        VnFlags::ADDRFORCE,
        VnFlags::SPACEBASE,
        VnFlags::INDIRECT_CREATION,
        VnFlags::RETURN_ADDRESS,
    ];
    let mut clones: Vec<(OpId, OpId)> = Vec::new();
    let mut orig_to_clone: HashMap<OpId, OpId> = HashMap::new();
    for orig in fd.blocks.block(b).ops.clone() {
        let o = fd.op(orig).clone();
        if o.is_branch() {
            if o.opc != Opcode::Branch {
                return err("Cannot duplicate 2-way or n-way branch in nodeplit");
            }
            continue;
        }
        let dup = fd.new_op(o.opc, o.seq.addr);
        for f in OP_KEEP.into_iter().filter(|&f| o.flags.has(f)) {
            fd.op_mut(dup).flags.set(f);
        }
        fd.op_mut(dup).halt = o.halt;
        clones.push((dup, orig));
        orig_to_clone.insert(orig, dup);
        if let Some(out) = o.out {
            let v = fd.vn(out).clone();
            let nv = fd.new_varnode_out(v.size, v.space, v.offset, dup);
            for f in VN_KEEP.into_iter().chain([VnFlags::WRITEMASK]).filter(|&f| v.flags.has(f)) {
                fd.vn_set(nv, f);
            }
        }
        fd.op_insert_end(dup, bprime);
    }
    patch_inputs(fd, &clones, &orig_to_clone, inedge)
}

/// `CloneBlockOps::patchInputs`.
fn patch_inputs(fd: &mut Funcdata, clones: &[(OpId, OpId)], map: &HashMap<OpId, OpId>, inedge: usize) -> Result<()> {
    for &(dup, orig) in clones {
        let o = fd.op(orig).clone();
        if o.opc == Opcode::Multiequal {
            fd.op_set_opcode(dup, Opcode::Copy);
            let Some(&vn) = o.ins.get(inedge) else { return err("MULTIEQUAL lacks the split edge's input") };
            fd.op_set_input(dup, vn, 0)?;
            fd.op_remove_input(orig, inedge);
            if fd.op(orig).ins.len() == 1 {
                fd.op_set_opcode(orig, Opcode::Copy);
            }
        } else if o.opc == Opcode::Indirect {
            return err("Can't clone INDIRECTs");
        } else if o.is_call() {
            return err("Can't clone CALLs");
        } else {
            for (i, &ov) in o.ins.iter().enumerate() {
                let v = fd.vn(ov);
                let cv: VarnodeId = if v.is_constant() {
                    ov
                } else if v.is_annotation() {
                    // newCodeRef: a one-byte code reference at the same address
                    let (space, offset) = (v.space, v.offset);
                    let nv = fd.new_varnode(1, space, offset);
                    fd.vn_set(nv, VnFlags::CODEREF);
                    nv
                } else if v.is_free() {
                    return err("Can't clone free varnode");
                } else {
                    v.def.and_then(|d| map.get(&d)).and_then(|&c| fd.op(c).out).unwrap_or(ov)
                };
                fd.op_set_input(dup, cv, i)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! A hand-built graph; the expected result is derived by hand from the C++
    //! (blockaction.cc `ActionReturnSplit`, funcdata_block.cc `nodeSplit`), not run on the
    //! reference.
    use super::*;

    /// The graph of `structure.rs`'s `trace_dag_goto` (A -> {B, C}, B -> {D, E}, C -> {D, E},
    /// D -> F, E -> F) with F a RETURN: the collapse makes E -> F a plain goto (Basic Block 4 in
    /// that tree is E), which prints (the flow after it reaches D, not F), so in-edge 1 of F (from
    /// E) is split off; in-edge 0 (from D) stays.
    #[test]
    fn splits_goto_return() {
        let mut fd = Funcdata::new(0x1000);
        fd.uniq = Some(1);
        let b: Vec<BlockId> = (0..6).map(|i| fd.blocks.new_block(0x1000 + 0x10 * i)).collect();
        fd.blocks.set_start_block(b[0]);
        for (f, t) in [(0, 1), (0, 2), (1, 3), (1, 4), (2, 3), (2, 4), (3, 5), (4, 5)] {
            fd.blocks.add_edge(b[f], b[t]);
        }
        for bl in [b[0], b[1], b[2]] {
            let start = fd.blocks.block(bl).start;
            let cb = fd.new_op(Opcode::Cbranch, start);
            let (d, k) = (fd.new_constant(4, 0), fd.new_constant(1, 1));
            fd.op_set_input(cb, d, 0).unwrap();
            fd.op_set_input(cb, k, 1).unwrap();
            fd.op_insert_end(cb, bl);
        }
        let ret = fd.new_op(Opcode::Return, 0x1050);
        let zero = fd.new_constant(4, 0);
        fd.op_set_input(ret, zero, 0).unwrap();
        fd.op_insert_end(ret, b[5]);
        fd.blocks.structure_loops().unwrap();
        super::super::structure::build_and_collapse(&mut fd).unwrap();
        let s = std::mem::take(&mut fd.structure);
        let splits = find_splits(&fd, &s).unwrap();
        fd.structure = s;
        assert_eq!(splits, vec![(b[5], 1)]);
        node_split(&mut fd, b[5], 1).unwrap();
        let nb = BlockId(6);
        assert_eq!(fd.blocks.block(b[4]).outs.iter().map(|e| e.point).collect::<Vec<_>>(), vec![nb]);
        assert_eq!(fd.blocks.block(b[5]).ins.len(), 1);
        let ops = &fd.blocks.block(nb).ops;
        assert_eq!(ops.len(), 1);
        // opSetInput clones a constant that already has a reader, so the copy reads a new #0
        let ins = &fd.op(ops[0]).ins;
        assert_eq!((fd.op(ops[0]).opc, ins.len()), (Opcode::Return, 1));
        assert!(ins[0] != zero && fd.vn(ins[0]).is_constant() && fd.vn(ins[0]).offset == 0);
        assert!(fd.structure.is_empty());
    }
}
