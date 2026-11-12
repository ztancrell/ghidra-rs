//! The action framework: port of `Action`, `ActionGroup` and `ActionRestartGroup` (action.cc)
//! with `break start` breakpoints, so that a run stops before an action and `continue` resumes
//! it where it stopped. Rule pools (`ActionPool`) come with the rules.

use super::{err, Arch, Funcdata, Result};

/// An action's body: it edits the function and returns how many changes it made (the C++
/// `count += ...` inside `apply`).
pub(crate) type ApplyFn = fn(&mut Funcdata, &Arch) -> Result<i32>;

/// Index of an action in its [`ActionTree`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActionId(usize);

/// `Action::status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Start,
    BreakStartHit,
    Repeat,
    Mid,
    End,
}

/// What an action is: one action, or a group of them run in order.
#[derive(Debug, Clone)]
enum Kind {
    Leaf(ApplyFn),
    /// `ActionGroup`; `restart`: an `ActionRestartGroup`
    Group {
        kids: Vec<ActionId>,
        restart: bool,
    },
}

/// One action with the C++ `Action` fields that drive `perform`.
#[derive(Debug, Clone)]
struct Node {
    name: &'static str,
    kind: Kind,
    /// `rule_repeatapply`: apply again while it changes something
    repeat: bool,
    /// `rule_onceperfunc`: apply once per function
    once: bool,
    status: Status,
    count: i32,
    /// the changes before the last `apply` (`lcount`)
    lcount: i32,
    /// the group's current member (`ActionGroup::state`)
    state: usize,
    /// `ActionRestartGroup::curstart`: -1 once finished
    curstart: i32,
    /// `break_start`
    break_start: bool,
}

/// An action tree: the root is the first node added.
#[derive(Debug, Clone, Default)]
pub struct ActionTree {
    nodes: Vec<Node>,
}

/// What a run of [`ActionTree::perform`] ended with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// stopped at a breakpoint: the path `Break at <path>` prints
    Break(String),
    /// the root finished
    Complete,
}

impl ActionTree {
    fn add(&mut self, name: &'static str, kind: Kind, repeat: bool, once: bool) -> ActionId {
        self.nodes.push(Node {
            name,
            kind,
            repeat,
            once,
            status: Status::Start,
            count: 0,
            lcount: 0,
            state: 0,
            curstart: 0,
            break_start: false,
        });
        ActionId(self.nodes.len() - 1)
    }

    /// A single action.
    pub(crate) fn leaf(&mut self, name: &'static str, apply: ApplyFn) -> ActionId {
        self.add(name, Kind::Leaf(apply), false, false)
    }

    /// An `ActionGroup` (`repeat`: `rule_repeatapply`).
    pub(crate) fn group(&mut self, name: &'static str, kids: Vec<ActionId>, repeat: bool) -> ActionId {
        self.add(name, Kind::Group { kids, restart: false }, repeat, false)
    }

    /// An `ActionRestartGroup` applied once per function (the universal root).
    pub(crate) fn restart_group(&mut self, name: &'static str, kids: Vec<ActionId>) -> ActionId {
        self.add(name, Kind::Group { kids, restart: true }, false, true)
    }

    fn root(&self) -> ActionId {
        ActionId(self.nodes.len() - 1)
    }

    /// Port of `Action::setBreakPoint(break_start, name)`.
    pub fn set_break_start(&mut self, name: &str) -> Result<()> {
        match self.nodes.iter_mut().find(|n| n.name == name) {
            Some(n) => {
                n.break_start = true;
                Ok(())
            }
            None => err(format!("break start {name}: action not ported yet (stage S2 ends at paramdouble)")),
        }
    }

    /// Port of `Action::perform` on the root: run, or resume after a breakpoint.
    pub fn perform(&mut self, fd: &mut Funcdata, arch: &Arch) -> Result<Outcome> {
        let root = self.root();
        if self.perform_node(root, fd, arch)? < 0 {
            let mut path = String::new();
            self.print_state(root, &mut path);
            return Ok(Outcome::Break(path));
        }
        Ok(Outcome::Complete)
    }

    /// Port of `Action::perform`: apply (again while a repeating action changes something) and
    /// return the changes made, or -1 when a breakpoint stopped it.
    fn perform_node(&mut self, id: ActionId, fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
        loop {
            let n = &mut self.nodes[id.0];
            match n.status {
                Status::End => return Ok(0),
                Status::Start => {
                    n.count = 0;
                    if n.break_start {
                        n.status = Status::BreakStartHit;
                        return Ok(-1);
                    }
                    n.lcount = n.count;
                }
                Status::BreakStartHit | Status::Repeat => n.lcount = n.count,
                Status::Mid => {}
            }
            let res = self.apply(id, fd, arch)?;
            let n = &mut self.nodes[id.0];
            if res < 0 {
                n.status = Status::Mid;
                return Ok(res);
            }
            n.status = Status::Repeat;
            if !(n.lcount < n.count && n.repeat) {
                break;
            }
        }
        let n = &mut self.nodes[id.0];
        n.status = if n.once { Status::End } else { Status::Start };
        Ok(n.count)
    }

    /// The `apply` of each kind: `ActionGroup::apply` runs the members from where it stopped;
    /// `ActionRestartGroup::apply` runs once more while the function asks for a restart (nothing
    /// ported asks yet, so it finishes after one run).
    fn apply(&mut self, id: ActionId, fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
        let (kids, restart) = match &self.nodes[id.0].kind {
            Kind::Leaf(f) => {
                let changes = f(fd, arch)?;
                self.nodes[id.0].count += changes;
                return Ok(0);
            }
            Kind::Group { kids, restart } => (kids.clone(), *restart),
        };
        if restart && self.nodes[id.0].curstart == -1 {
            return Ok(0);
        }
        if self.nodes[id.0].status != Status::Mid {
            self.nodes[id.0].state = 0;
        }
        while let Some(&kid) = kids.get(self.nodes[id.0].state) {
            let res = self.perform_node(kid, fd, arch)?;
            if res > 0 {
                self.nodes[id.0].count += res;
            } else if res < 0 {
                return Ok(-1);
            }
            self.nodes[id.0].state += 1;
        }
        if restart {
            self.nodes[id.0].curstart = -1;
        }
        Ok(0)
    }

    /// Port of `Action::printState` and `ActionGroup::printState`: the path to the action a
    /// breakpoint stopped at.
    fn print_state(&self, id: ActionId, s: &mut String) {
        let n = &self.nodes[id.0];
        s.push_str(n.name);
        match n.status {
            Status::Start | Status::BreakStartHit | Status::Repeat => s.push_str(" start"),
            Status::Mid => s.push(':'),
            Status::End => s.push_str(" end"),
        }
        if let (Status::Mid, Kind::Group { kids, .. }) = (n.status, &n.kind) {
            if let Some(&kid) = kids.get(n.state) {
                self.print_state(kid, s);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::Image;

    fn change(_: &mut Funcdata, _: &Arch) -> Result<i32> {
        Ok(1)
    }
    fn nothing(_: &mut Funcdata, _: &Arch) -> Result<i32> {
        Ok(0)
    }

    /// A break inside a repeating group stops there on each pass; `continue` resumes it.
    #[test]
    fn break_and_continue_in_a_repeating_group() {
        let Ok(sleigh) = crate::sleigh::Sleigh::load(&crate::sleigh::Sleigh::sla_path("x86")) else { return };
        let cspec = std::fs::read_to_string(crate::sleigh::Sleigh::sla_path("x86").with_file_name("x86win.cspec"));
        let Ok(cspec) = cspec else { return };
        let Ok(arch) = Arch::new(sleigh, Image::default(), &cspec) else { return };
        let mut t = ActionTree::default();
        let a = t.leaf("a", nothing);
        let b = t.leaf("b", change);
        let inner = t.group("inner", vec![a, b], true);
        t.restart_group("root", vec![inner]);
        t.set_break_start("a").unwrap();
        let mut fd = Funcdata::new(0);
        assert_eq!(t.perform(&mut fd, &arch).unwrap(), Outcome::Break("root:inner:a start".into()));
        // b changes something each time, so the group repeats and stops at a again
        assert_eq!(t.perform(&mut fd, &arch).unwrap(), Outcome::Break("root:inner:a start".into()));
    }
}
