use core::sync::atomic::*;

// TODO cache-align fields
/// A simple spinlock based on the ticketlock concept
pub struct Spinlock {
    assigned_tickets: AtomicUsize,
    active_ticket: AtomicUsize,
}

impl Spinlock {
    pub const fn new() -> Self {
        Spinlock {
            assigned_tickets: AtomicUsize::new(0),
            active_ticket: AtomicUsize::new(0),
        }
    }

    pub fn lock(&self) {
        // fetch new ticket
        let ticket = self.assigned_tickets.fetch_add(1, Ordering::SeqCst);

        // spin as lock as it is not our turn
        while self.active_ticket.load(Ordering::SeqCst) != ticket {
            unsafe {
                #[cfg(target_arch = "x86")]
                core::arch::x86::_mm_pause();
                #[cfg(target_arch = "x86_64")]
                core::arch::x86_64::_mm_pause();
            }
        }
    }

    pub fn release(&self) {
        self.active_ticket.fetch_add(1, Ordering::SeqCst);
    }
}

impl Default for Spinlock {
    fn default() -> Self {
        Spinlock::new()
    }
}

// Same unsafe impls as `std::sync::Mutex`
unsafe impl Sync for Spinlock {}
unsafe impl Send for Spinlock {}
