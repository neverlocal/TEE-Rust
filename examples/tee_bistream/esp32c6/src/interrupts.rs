////////////////
// INTERRUPTS //
////////////////
 
use defmt::debug;

use core::cell::{RefCell, Cell};
use critical_section::{CriticalSection, Mutex};


use esp_hal::{
    gpio::{Input, Output},
    handler,
    ram,
    time::{self, Duration, Instant},
};

pub static RECEIVING_PIN: Mutex<RefCell<Option<Input>>> = Mutex::new(RefCell::new(None));
pub static HERALD_PIN: Mutex<RefCell<Option<Input>>> = Mutex::new(RefCell::new(None));
pub static OUTCOME0_PIN: Mutex<RefCell<Option<Input>>> = Mutex::new(RefCell::new(None));
pub static OUTCOME1_PIN: Mutex<RefCell<Option<Input>>> = Mutex::new(RefCell::new(None));

#[handler]
#[ram] //Placed in RAM for faster execution
pub fn handler() {
    critical_section::with(|receiving_sec| {
        let mut receiving_pin = RECEIVING_PIN.borrow_ref_mut(receiving_sec);
        let receiving_pin = receiving_pin.as_mut().unwrap();
        if receiving_pin.is_interrupt_set() {
            debug!("[ handler ] RECEIVING was the source of the interrupt");
            if receiving_pin.is_high() {
                start_cycle(receiving_sec);
            } else {
                stop_cycle(receiving_sec);
            }
            receiving_pin.clear_interrupt();
        }
    });

    critical_section::with(|herald_sec| {
        let mut herald_pin = HERALD_PIN.borrow_ref_mut(herald_sec);
        let herald_pin = herald_pin.as_mut().unwrap();
        if herald_pin.is_interrupt_set() {
            debug!("[ handler ] HERALD was the source of the interrupt");
            see_herald(herald_sec);
            herald_pin.clear_interrupt();
        }
    });

    critical_section::with(|outcome0_sec| {
        let mut outcome0_pin = OUTCOME0_PIN.borrow_ref_mut(outcome0_sec);
        let outcome0_pin = outcome0_pin.as_mut().unwrap();
        if outcome0_pin.is_interrupt_set() {
            debug!("[ handler ] OUTCOME0 was the source of the interrupt");
            see_outcome0(outcome0_sec);
            outcome0_pin.clear_interrupt();
        }
    });

    critical_section::with(|outcome1_sec| {
        let mut outcome1_pin = OUTCOME1_PIN.borrow_ref_mut(outcome1_sec);
        let outcome1_pin = outcome1_pin.as_mut().unwrap();
        if outcome1_pin.is_interrupt_set() {
            debug!("[ handler ] OUTCOME1 was the source of the interrupt");
            see_outcome1(outcome1_sec);
            outcome1_pin.clear_interrupt();
        }
    });
}

/////////////////////////////
// MEASUREMENT ACQUISITION //
/////////////////////////////

// Constants
#[ram]
static OUTCOME_DELAY_US: u64 = 500;
#[ram]
static OUTCOME_DELAY_STDDEV_US: u64 = 50;
#[ram]
static MIN_OUTCOME_DELAY_US: u64 = OUTCOME_DELAY_US-3*OUTCOME_DELAY_STDDEV_US;
#[ram]
static MAX_OUTCOME_DELAY_US: u64 = OUTCOME_DELAY_US+3*OUTCOME_DELAY_STDDEV_US;

// Variables
#[ram]
pub static CYCLE: Mutex<Cell<usize>> = Mutex::new(Cell::new(0));
#[ram]
pub static RECEIVING_STATUS: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));
#[ram]
pub static HERALD_SEEN: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));
#[ram]
static HERALD_LOCKED: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));
#[ram]
static HERALD_TIME: Mutex<Cell<Instant>> = Mutex::new(Cell::new(time::Instant::EPOCH));
#[ram]
pub static OUTCOME0_SEEN: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));
#[ram]
pub static OUTCOME1_SEEN: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));

// Starts a new bit reception cycle.
//
// A cycle is the period during which the TEE expects to receive a single bit of data from the generator,
// although in reality the process is noisy and the bit may not be received correctly.
#[ram]
fn start_cycle(cs: CriticalSection<'_>) {
    debug!("[ start_cycle ] Starting cycle.");
    HERALD_SEEN.borrow(cs).set(false);
    HERALD_LOCKED.borrow(cs).set(false);
    OUTCOME0_SEEN.borrow(cs).set(false);
    OUTCOME1_SEEN.borrow(cs).set(false);
    RECEIVING_STATUS.borrow(cs).set(true);
    debug!("[ start_cycle ] Cycle started.");
}

// Stops the current bit reception cycle.
//
// A cycle is the period during which the TEE expects to receive a single bit of data from the generator,
// although in reality the process is noisy and the bit may not be received correctly.
//
#[ram]
fn stop_cycle(cs: CriticalSection<'_>) {
    debug!("[ stop_cycle ] Stopping cycle.");
    RECEIVING_STATUS.borrow(cs).set(false);
    let cycle = CYCLE.borrow(cs);
    cycle.set(cycle.get() + 1);
    debug!("[ stop_cycle ] Cycle stopped.");
}

// Records that a herald photon has been observed in this bit reception cycle.
//
// Observation of a herald photon pre-empts the potential observation of a data photon, but it is not
// necessarily the case that the first herald photon observed is one which will be followed by a data photon.
// As a consequence, the time of herald photon observation is updated at each observation, until the first
// data photon is received (at which point the herald photon time is locked).
#[ram] //Placed in RAM for faster execution
fn see_herald(cs: CriticalSection<'_>) {
        if !RECEIVING_STATUS.borrow(cs).get() || HERALD_LOCKED.borrow(cs).get()
        {
            debug!( "[ see_herald ] triggered at the wrong time." );
            return
        } else {
            debug!( "[ see_herald ] triggered at the right time." );
            HERALD_TIME.borrow(cs).set(Instant::now());
            debug!( "[ see_herald ] herald_time: {}", HERALD_TIME.borrow(cs).get() );
            HERALD_SEEN.borrow(cs).set(true);
        }
}

// Records that a data photon has been measured with outcome 0 in this bit reception cycle.
// 
// Measurement of a data photon is only recorded if it happens after observation of a herald photon,
// within a pre-defined time window based on the time delays expected from the quantum HW setup.
#[ram] //Placed in RAM for faster execution
fn see_outcome0(cs: CriticalSection<'_>) {
    if !RECEIVING_STATUS.borrow(cs).get() || !HERALD_SEEN.borrow(cs).get()
        {
            debug!( "[ see_outcome0 ] triggered at the wrong time." );
            return
        } else {
            debug!( "[ see_outcome0 ] triggered at the right time." );
            let delay: Duration = Instant::now() - HERALD_TIME.borrow(cs).get();
            if delay.as_micros() >= MIN_OUTCOME_DELAY_US && delay.as_micros() <= MAX_OUTCOME_DELAY_US {
                debug!( "[ see_outcome0 ] delay: {:?}", delay.as_micros() );
                HERALD_LOCKED.borrow(cs).set(true);
                OUTCOME0_SEEN.borrow(cs).set(true);
            }
        }
}

// Records that a data photon has been measured with outcome 0 in this bit reception cycle.
// 
// Measurement of a data photon is only recorded if it happens after observation of a herald photon,
// within a pre-defined time window based on the time delays expected from the quantum HW setup.
#[ram] //Placed in RAM for faster execution
fn see_outcome1(cs: CriticalSection<'_>) {
    //if (!CYCLE.borrow())
        if !RECEIVING_STATUS.borrow(cs).get() || !HERALD_SEEN.borrow(cs).get() {
            debug!( "[ see_outcome1 ] triggered at the wrong time." );
            return
        } else {
            debug!( "[ see_outcome1 ] triggered at the right time." );
            let delay: Duration = Instant::now() - HERALD_TIME.borrow(cs).get();
            if delay.as_micros() >= MIN_OUTCOME_DELAY_US && delay.as_micros() <= MAX_OUTCOME_DELAY_US {
                debug!( "[ see_outcome1 ] delay: {:?}", delay.as_micros() );
                HERALD_LOCKED.borrow(cs).set(true);
                OUTCOME1_SEEN.borrow(cs).set(true);
            }
        }
}

// Sets the pin selecting the choice of measurement high or low.
pub fn set_basis(cs: CriticalSection<'_>, basis_select_pin: &mut Output<'_>, pin: bool) {
    if !RECEIVING_STATUS.borrow(cs).get() {
        if pin {
            basis_select_pin.set_high();
        } else {
            basis_select_pin.set_low();
        }
    }
}
