//! The order a pipeline run's histories take their arena slots in: chunk order.
//!
//! The run's sequencer passes records on in chunk order, and a record keeps its slot until it
//! drops, so the records of later chunks wait behind an earlier chunk still replaying, each in its
//! slot. Granted first come, first served, they and the later replays can hold every slot while the
//! earlier chunk waits for one only they could free, and the run stops for good. Granted in order,
//! the slots are held only by chunks before the first one waiting and by that chunk's earlier
//! segments. The chunks before it reach the sequencer and drop, so it gets a slot as long as the
//! arena has as many as a chunk has segments, which the pipeline checks before it starts.
//!
//! - The run's snapshot thread gives each snapshot it queues a [`GrantTicket`], in queue order:
//!   chunk order, with a split chunk's segments one after another, so a chunk's segments are
//!   granted as one, in segment order. A take in its turn ([`HistoryArena::take_in_turn`]) waits
//!   until every earlier ticket has taken a slot or been dropped, and lets the next one go once it
//!   has its own.
//! - A ticket that never takes gives its turn up when it drops, however its snapshot ends: a chunk
//!   emulated to nothing, a failed replay, a snapshot drained unreplayed. The workers take
//!   snapshots off the queue in order, so every ticket a take waits on is held by a live worker,
//!   which takes or drops it.
//! - A worker makes its ticket the thread's turn while it replays ([`GrantTicket::enter`]), and the
//!   history writer takes in that turn ([`with_turn`]): the writer sits inside the interpreter or
//!   the AOT core, neither of which carries a ticket.
//! - [`GrantOrder::close`], for a run that failed, ends every wait for a turn, and every wait for a
//!   slot made in one: such a take gives up and its history stays on the heap, so a replay that
//!   would otherwise wait on slots the failed run never frees finishes, and its worker can stop.
//! - A take with no turn, a fill or a history written outside a pipeline replay, is not ordered.
//!
//! [`HistoryArena::take_in_turn`]: super::HistoryArena::take_in_turn

use std::{
    cell::RefCell,
    collections::BTreeSet,
    marker::PhantomData,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
    },
};

use crossbeam::channel::{bounded, Receiver, Sender};

/// One run's order of grants.
pub struct GrantOrder {
    issued: AtomicU64,
    granted: Mutex<Granted>,
    changed: Condvar,
    /// Disconnected at the close, which a wait for a slot selects on; nothing is ever sent.
    closed: Receiver<()>,
}

impl Default for GrantOrder {
    fn default() -> Self {
        let (open, closed) = bounded(0);
        Self {
            issued: AtomicU64::new(0),
            granted: Mutex::new(Granted {
                next: 0,
                ahead: BTreeSet::new(),
                open: Some(open),
                #[cfg(test)]
                waiting: 0,
            }),
            changed: Condvar::new(),
            closed,
        }
    }
}

struct Granted {
    /// Every place before it has taken a slot or given its turn up.
    next: u64,
    /// The places past `next` that have.
    ahead: BTreeSet<u64>,
    /// [`GrantOrder::closed`]'s sender, until the close drops it.
    open: Option<Sender<()>>,
    /// Takes waiting for their turn, for a test that holds a turn until a later one waits.
    #[cfg(test)]
    waiting: usize,
}

impl Granted {
    fn is_due(&self, place: u64) -> bool {
        self.open.is_none() || place <= self.next
    }
}

impl GrantOrder {
    /// The next snapshot's ticket. One thread queues a run's snapshots and takes their tickets as
    /// it queues them, so the places follow the queue.
    pub fn ticket(self: &Arc<Self>) -> GrantTicket {
        GrantTicket {
            order: Arc::clone(self),
            place: self.issued.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// No take in turn waits, for its turn or a slot, from here on.
    pub fn close(&self) {
        self.lock().open = None;
        self.changed.notify_all();
    }

    /// Whether a take is waiting for its turn.
    #[cfg(test)]
    pub(crate) fn is_awaited(&self) -> bool {
        self.lock().waiting > 0
    }

    fn lock(&self) -> MutexGuard<'_, Granted> {
        self.granted.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn pass(&self, place: u64) {
        let mut granted = self.lock();
        let granted = &mut *granted;
        if place != granted.next {
            if place > granted.next {
                granted.ahead.insert(place);
            }
            return;
        }
        granted.next += 1;
        while granted.ahead.remove(&granted.next) {
            granted.next += 1;
        }
        self.changed.notify_all();
    }
}

/// A snapshot's place in its run's [`GrantOrder`]. Dropped, it gives its turn up.
pub struct GrantTicket {
    order: Arc<GrantOrder>,
    place: u64,
}

impl GrantTicket {
    /// Makes this the calling thread's turn until the guard drops, which drops the ticket.
    ///
    /// # Panics
    ///
    /// If the thread is in a turn already.
    #[must_use = "the turn ends when the guard drops"]
    pub fn enter(self) -> InTurn {
        TURN.with(|turn| {
            let mut turn = turn.borrow_mut();
            assert!(turn.is_none(), "a replay entered a turn inside another");
            *turn = Some(self);
        });
        InTurn(PhantomData)
    }

    /// Whether every earlier place has taken a slot or given its turn up.
    pub(super) fn is_due(&self) -> bool {
        self.order.lock().is_due(self.place)
    }

    pub(super) fn wait(&self) {
        let mut granted = self.order.lock();
        #[cfg(test)]
        {
            granted.waiting += 1;
        }
        while !granted.is_due(self.place) {
            granted = self
                .order
                .changed
                .wait(granted)
                .unwrap_or_else(PoisonError::into_inner);
        }
        #[cfg(test)]
        {
            granted.waiting -= 1;
        }
    }

    /// Disconnected once the order closes.
    pub(super) fn closed(&self) -> &Receiver<()> {
        &self.order.closed
    }

    /// The place has its slot: the next one may take.
    pub(super) fn granted(&self) {
        self.order.pass(self.place);
    }
}

impl Drop for GrantTicket {
    fn drop(&mut self) {
        self.order.pass(self.place);
    }
}

/// The calling thread's turn, held until this drops. Not `Send`: it ends the turn of the thread
/// that entered it.
pub struct InTurn(PhantomData<*const ()>);

impl Drop for InTurn {
    fn drop(&mut self) {
        // `try_with`: at thread exit the cell may be gone already, and its ticket dropped with it.
        drop(TURN.try_with(RefCell::take));
    }
}

thread_local! {
    static TURN: RefCell<Option<GrantTicket>> = const { RefCell::new(None) };
}

/// `f` on the calling thread's turn, if it is in one.
pub fn with_turn<R>(f: impl FnOnce(Option<&GrantTicket>) -> R) -> R {
    TURN.with(|turn| f(turn.borrow().as_ref()))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    /// Long enough for a thread that could go to have gone.
    const SETTLE: Duration = Duration::from_millis(100);

    fn tickets(count: usize) -> (Arc<GrantOrder>, Vec<GrantTicket>) {
        let order = Arc::new(GrantOrder::default());
        let tickets = (0..count).map(|_| order.ticket()).collect();
        (order, tickets)
    }

    /// Each ticket on a thread of its own, started last to first, each sending its place once it
    /// is due and then letting the next one go: the places come back in order.
    #[test]
    fn places_are_due_in_queue_order_whatever_order_they_ask_in() {
        let (_order, tickets) = tickets(4);
        let (sent, got) = mpsc::channel();
        let takers: Vec<_> = tickets
            .into_iter()
            .rev()
            .map(|ticket| {
                let sent = sent.clone();
                let taker = thread::spawn(move || {
                    ticket.wait();
                    sent.send(ticket.place).expect("the test receives");
                    ticket.granted();
                });
                thread::sleep(SETTLE / 4);
                taker
            })
            .collect();
        drop(sent);
        for taker in takers {
            taker.join().expect("a taker");
        }
        assert_eq!(got.iter().collect::<Vec<_>>(), [0, 1, 2, 3]);
    }

    #[test]
    fn a_later_place_is_not_due_until_every_earlier_one_has_passed() {
        let (_order, mut tickets) = tickets(3);
        let third = tickets.pop().expect("three");
        assert!(!third.is_due());
        tickets[1].granted();
        assert!(!third.is_due(), "place 0 has not passed");
        tickets[0].granted();
        assert!(third.is_due());
    }

    /// A chunk emulated to nothing, a failed replay or a drained snapshot drops its ticket
    /// without a take; the place after it must not wait for it.
    #[test]
    fn a_ticket_dropped_without_a_take_gives_its_turn_up() {
        let (_order, mut tickets) = tickets(2);
        let second = tickets.pop().expect("two");
        let waiter = thread::spawn(move || second.wait());
        thread::sleep(SETTLE);
        assert!(!waiter.is_finished(), "place 1 went before place 0");
        drop(tickets);
        waiter.join().expect("the waiter");
    }

    /// A replay that took a slot drops its ticket at its end, and a second take of the same
    /// place does not wait: neither may count twice nor move anything back.
    #[test]
    fn a_place_that_has_passed_passes_again_without_effect() {
        let (_order, mut tickets) = tickets(3);
        let third = tickets.pop().expect("three");
        tickets[0].granted();
        assert!(tickets[0].is_due());
        tickets[0].granted();
        drop(tickets.remove(0));
        assert!(!third.is_due(), "place 1 has not passed");
        drop(tickets);
        assert!(third.is_due());
    }

    /// A wait for a turn ends, and the signal a wait for a slot selects on fires, for every
    /// ticket, issued before the close or after it.
    #[test]
    fn closing_the_order_ends_every_wait() {
        let (order, mut tickets) = tickets(3);
        let third = tickets.pop().expect("three");
        assert!(third.closed().try_recv().is_err_and(|e| e.is_empty()));
        let waiter = thread::spawn(move || {
            third.wait();
            third.closed().recv().is_err()
        });
        thread::sleep(SETTLE);
        assert!(!waiter.is_finished());
        order.close();
        let started = Instant::now();
        assert!(
            waiter.join().expect("the waiter"),
            "the close sent something"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        let late = order.ticket();
        assert!(late.is_due(), "a ticket issued after the close");
        assert!(late.closed().try_recv().is_err_and(|e| e.is_disconnected()));
    }

    #[test]
    fn a_wait_for_a_turn_is_seen_while_it_lasts() {
        let (order, mut tickets) = tickets(2);
        let second = tickets.pop().expect("two");
        assert!(!order.is_awaited());
        let waiter = thread::spawn(move || second.wait());
        let started = Instant::now();
        while !order.is_awaited() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the wait is not seen"
            );
            thread::yield_now();
        }
        drop(tickets);
        waiter.join().expect("the waiter");
        assert!(!order.is_awaited());
    }

    #[test]
    fn a_turn_is_the_threads_until_its_guard_drops_and_then_given_up() {
        let (_order, mut tickets) = tickets(2);
        let second = tickets.pop().expect("two");
        let first = tickets.pop().expect("one");
        assert_eq!(with_turn(|turn| turn.map(|t| t.place)), None);
        let in_turn = first.enter();
        assert_eq!(with_turn(|turn| turn.map(|t| t.place)), Some(0));
        let elsewhere = thread::spawn(|| with_turn(|turn| turn.is_some()));
        assert!(!elsewhere.join().expect("another thread"), "a turn leaked");
        assert!(!second.is_due());
        drop(in_turn);
        assert_eq!(with_turn(|turn| turn.map(|t| t.place)), None);
        assert!(second.is_due(), "the guard's drop gave the turn up");
    }

    #[test]
    #[should_panic(expected = "a replay entered a turn inside another")]
    fn a_turn_inside_another_is_refused() {
        let (_order, mut tickets) = tickets(2);
        let _outer = tickets.remove(0).enter();
        let _inner = tickets.remove(0).enter();
    }
}
