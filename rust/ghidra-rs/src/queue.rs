//! Ghidra's auto-analysis task queue: `AutoAnalysisManager` with its `AnalysisTaskList`s (one
//! per `AnalyzerType`), each analyzer's `AnalysisScheduler` and the `PriorityQueue` of tasks.
//! A change notifies every analyzer of its type: the scheduler adds the addresses to its set
//! and, unless it is queued already, queues one task at the analyzer's priority. The next task
//! is the first queued at the lowest priority number; running it hands the analyzer its set
//! and clears it. Which analyzers there are, and what they do, is the caller's (`T`).
// ponytail: no background commands (`schedule(cmd, priority)`: CreateFunctionCmd,
// DisassembleCommand); add them as a second kind of queue item when an analyzer queues one.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// `AnalysisPriority`: lower runs first.
pub mod priority {
    pub const FORMAT_ANALYSIS: i32 = 100;
    pub const BLOCK_ANALYSIS: i32 = 200;
    pub const DISASSEMBLY: i32 = 300;
    pub const CODE_ANALYSIS: i32 = 400;
    pub const FUNCTION_ANALYSIS: i32 = 500;
    pub const REFERENCE_ANALYSIS: i32 = 600;
    pub const DATA_ANALYSIS: i32 = 700;
    pub const FUNCTION_ID_ANALYSIS: i32 = 800;
    pub const DATA_TYPE_PROPOGATION: i32 = 900;
    pub const LOW_PRIORITY: i32 = 10000;
}

/// `AnalyzerType`: the change an analyzer is notified of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// memory blocks added (`BYTE_ANALYZER`)
    Byte,
    /// code defined (`INSTRUCTION_ANALYZER`)
    Instruction,
    /// functions added (`FUNCTION_ANALYZER`)
    Function,
    /// data defined (`DATA_ANALYZER`)
    Data,
}

/// One analyzer: its name (which orders analyzers of one priority), type and priority.
pub struct Analyzer<T> {
    pub name: &'static str,
    pub kind: Kind,
    pub priority: i32,
    pub id: T,
}

struct Scheduler<T> {
    analyzer: Analyzer<T>,
    added: BTreeSet<u32>,
    scheduled: bool,
}

pub struct Manager<T> {
    // sorted by priority, then name (AnalysisTaskList's comparator)
    schedulers: Vec<Scheduler<T>>,
    // priority -> scheduler indices, first queued first
    queue: BTreeMap<i32, VecDeque<usize>>,
}

impl<T: Copy> Manager<T> {
    pub fn new(mut analyzers: Vec<Analyzer<T>>) -> Manager<T> {
        analyzers.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.name.cmp(b.name)));
        let schedulers = analyzers
            .into_iter()
            .map(|analyzer| Scheduler { analyzer, added: BTreeSet::new(), scheduled: false })
            .collect();
        Manager { schedulers, queue: BTreeMap::new() }
    }

    /// `AnalysisTaskList.notifyAdded` for the analyzers of `kind`: each adds `addrs` to its set
    /// and is queued unless it is already (`AnalysisScheduler.added`, `schedule`).
    pub fn notify(&mut self, kind: Kind, addrs: &BTreeSet<u32>) {
        if addrs.is_empty() {
            return;
        }
        for (i, s) in self.schedulers.iter_mut().enumerate().filter(|(_, s)| s.analyzer.kind == kind) {
            s.added.extend(addrs);
            if !s.scheduled {
                s.scheduled = true;
                self.queue.entry(s.analyzer.priority).or_default().push_back(i);
            }
        }
    }

    /// The next task (`getNextTask`, `PriorityQueue.removeFirst`) and the set it analyzes
    /// (`AnalysisScheduler.runAnalyzer` takes the set and clears it).
    pub fn next_task(&mut self) -> Option<(T, BTreeSet<u32>)> {
        let mut first = self.queue.first_entry()?;
        let i = first.get_mut().pop_front()?;
        if first.get().is_empty() {
            first.remove();
        }
        let s = &mut self.schedulers[i];
        s.scheduled = false;
        Some((s.analyzer.id, std::mem::take(&mut s.added)))
    }
}

#[cfg(test)]
mod tests {
    use super::{priority, Analyzer, Kind, Manager};
    use std::collections::BTreeSet;

    #[test]
    fn lowest_priority_first_then_queued_order() {
        let a = |name, kind, priority, id| Analyzer { name, kind, priority, id };
        let mut m = Manager::new(vec![
            a("Purge", Kind::Function, priority::FUNCTION_ANALYSIS, 1),
            a("B", Kind::Byte, priority::DATA_TYPE_PROPOGATION - 1, 2),
            a("A", Kind::Byte, priority::BLOCK_ANALYSIS, 3),
        ]);
        let set = |v: &[u32]| v.iter().copied().collect::<BTreeSet<u32>>();
        m.notify(Kind::Byte, &set(&[0x400000]));
        assert_eq!(m.next_task().map(|t| t.0), Some(3));
        // functions found by A: the purge (500) runs before B (899)
        m.notify(Kind::Function, &set(&[0x20, 0x10]));
        m.notify(Kind::Function, &set(&[0x30])); // already queued: added to its set
        assert_eq!(m.next_task(), Some((1, set(&[0x10, 0x20, 0x30]))));
        assert_eq!(m.next_task().map(|t| t.0), Some(2));
        assert_eq!(m.next_task(), None);
    }
}
