use alloc::vec::Vec; // Needed for buffer manipulation

use rand::prelude::*;
use rand::distr::StandardUniform;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use rand_distr::{Distribution, Exp, Normal, Uniform};

use conjugate_coding::conjugate_coding::ConjugateCodingPrepare;
use crate::bit_ops::{self, read_nth_bit};

use esp_hal::{
    delay::Delay,
    gpio::{Input, Output},
    rng::Trng,
};

/////////////////
//  CONSTANTS  //
/////////////////

// APPARATUS SPECS //
const HD: f32 = 0.12371;
const H : f32 = 0.12371 + 0.49546;
const D : f32 = 0.12371 + 0.49546 + 0.38071;
const DD: f32 = 0.12371 + 0.49546 + 0.38071 + 0.00009;

const DD_M  : f32 = 500.0;
const DD_DEV: f32 = 50.0;

const LAMBDA: f32 = 1.0/1000.0;

const REAL_DELAY_TIME: u32 = (1.0 / (LAMBDA * (D + HD))) as u32;

// PULSES //
const PULSE_WIDTH: u32 = 1;
const STANDARD_DELAY_TIME: u32 = 2;
const IDLE_TIME:   u32 = 5;

/////////////////
//  TEST CASE  //
/////////////////
// Just a test, sends 0 each time basis pin is low and 1 every time it is high. Returns true when a cycle is run.
pub fn test(
    total_size       : usize,
    running         : Input<'_>,
    basis_select    : Input<'_>,
    mut sending         : Output<'_>,
    mut herald          : Output<'_>,
    mut outcome0        : Output<'_>,
    mut outcome1        : Output<'_>
) -> bool {
    if running.is_high() {
        let delay = Delay::new();
        for _n in 0..total_size {
            for _b in 0..16 {
                sending.set_high();
                delay.delay_micros(IDLE_TIME);

                fire_herald(&mut herald, delay);
                delay.delay_micros(STANDARD_DELAY_TIME);
                if basis_select.is_low() {
                    fire_outcomei(&mut outcome0, &mut outcome1, delay, false);
                } else {
                    fire_outcomei(&mut outcome0, &mut outcome1, delay, true);
                }

                delay.delay_micros(IDLE_TIME);
                sending.set_low();
                delay.delay_micros(IDLE_TIME);
            }
        }
        return true;
    }
    return false;
}

//////////////////
//  IDEAL CASE  //
//////////////////
// Sends information without any loss. Returns true when a cycle is run.
pub fn perfect(
    trng            : &mut Trng<'_>,
    preparation     : &ConjugateCodingPrepare,
    running         : &Input<'_>,
    basis_select    : &Input<'_>,
    sending         : &mut Output<'_>,
    herald          : &mut Output<'_>,
    outcome0        : &mut Output<'_>,
    outcome1        : &mut Output<'_>
) -> bool {
    if running.is_high() {
        let total_size  = preparation.total_size;
        let the_noises = generate_uniform_coinflip(trng, total_size); // Used to generate the bullshit bits
        let delay = Delay::new();
        for n in 0..total_size {
            let orderings = ConjugateCodingPrepare::orderings(&preparation)[n];
            let security0 = ConjugateCodingPrepare::security0(&preparation)[n];
            let security1 = ConjugateCodingPrepare::security1(&preparation)[n];
            for b in 0..8 {
                for c in 0..2 {
                    sending.set_high();
                    delay.delay_micros(IDLE_TIME);
                    // For each bit in orderings send two bits.
                    // Ordering = 0, c = 0 -> Send b in row 0
                    // Ordering = 0, c = 1 -> Send b in row 1
                    // Ordering = 1, c = 0 -> Send b in row 1
                    // Ordering = 1, c = 1 -> Send b in row 0
                    let sending_row = bit_ops::read_nth_bit(orderings, b) ^ (c == 1);
                    let data_bit: bool;
                    if sending_row {
                        data_bit = read_nth_bit(security1, b);
                    } else {
                        data_bit = read_nth_bit(security0, b);
                    }
                    fire_herald(herald, delay);
                    delay.delay_micros(STANDARD_DELAY_TIME);
                    if basis_select.is_high() == sending_row { // We are asking for the right row
                        fire_outcomei(outcome0, outcome1, delay, data_bit); // Real data
                    } else {
                        fire_outcomei(outcome0, outcome1, delay, read_nth_bit(the_noises[n], b)); // Noise
                    }
                    delay.delay_micros(IDLE_TIME);
                    sending.set_low();
                    delay.delay_micros(IDLE_TIME);
                }
            }
        }
        return true;
    }
    return false;
}

/////////////////
//  REAL CASE  //
/////////////////
// Sends information without any loss. Returns true when a cycle is run.
pub fn real(
    // trng            : &mut Trng<'_>,
    trng            : &mut Trng<'_>,
    preparation     : &ConjugateCodingPrepare,
    running         : &Input<'_>,
    basis_select    : &Input<'_>,
    sending         : &mut Output<'_>,
    herald          : &mut Output<'_>,
    outcome0        : &mut Output<'_>,
    outcome1        : &mut Output<'_>
) -> bool {
    if running.is_high() {

        // We prepare all the needed constants beforehand
        let total_size        = preparation.total_size;

        let delay = Delay::new();
        for n in 0..total_size {
            let the_noises      = generate_uniform_coinflip(trng, 1); // Used to generate the bullshit bits
            let orderings = ConjugateCodingPrepare::orderings(&preparation)[n];
            let security0 = ConjugateCodingPrepare::security0(&preparation)[n];
            let security1 = ConjugateCodingPrepare::security1(&preparation)[n];
            for b in 0..8 {
                for c in 0..2 {
                    let the_uniforms    = generate_uniform_vec(trng, 2);
                    let the_normals    = generate_normal_vec(trng, 4, DD_M, DD_DEV);
                    let the_exps       = generate_exp_vec(trng, 4, LAMBDA);
                    sending.set_high();
                    delay.delay_micros(IDLE_TIME);
                    // For each bit in orderings send two bits.
                    // Ordering = 0, c = 0 -> Send b in row 0
                    // Ordering = 0, c = 1 -> Send b in row 1
                    // Ordering = 1, c = 0 -> Send b in row 1
                    // Ordering = 1, c = 1 -> Send b in row 0
                    let sending_row = bit_ops::read_nth_bit(orderings, b) ^ (c == 1);
                    if basis_select.is_high() == sending_row { // We are asking for the right row, so we send real data
                        let data_bit: bool;
                        if sending_row {
                            data_bit = read_nth_bit(security1, b);
                        } else {
                            data_bit = read_nth_bit(security0, b);
                        }
                        fire_real(
                            outcome0,
                            outcome1,
                            herald,
                            delay,
                            data_bit,
                            the_uniforms[c],
                            the_normals[c],
                            the_normals[c+2],
                            the_exps[c],
                            the_exps[c+2]
                            );
                    } else { // We asked for the wrong row, so we send noise.
                        fire_real(
                            outcome0,
                            outcome1,
                            herald,
                            delay,
                            read_nth_bit(the_noises[n], b),
                            the_uniforms[c],
                            the_normals[c],
                            the_normals[c+2],
                            the_exps[c],
                            the_exps[c+2]
                            );
                    }
                    delay.delay_micros(IDLE_TIME);
                    sending.set_low();
                    delay.delay_micros(IDLE_TIME);
                }
            }
        }
        return true;
    }
    return false;
}

///////////////
//  HELPERS  //
///////////////

// RANDOM DISTRIBUTIONS //

// To model photon emission events, which exhibit a
// great deal of randomness, we draw an x from a
// uniform distribution on [0,1], and output an event
// Depending on where x lands. Cumulative function:
// ^               _________
// |          ___/|||||||||
// |      ___||||||||||||||
//_|_____/|||||||||||||||||__>
// |     |   |   |    |   |
// 0    HD   H   D   DD   1
//
//      x < HD : We see heralding and data photon;
// HD < x < H  : We see heralding photon only;
// H  < x < D  : We see data photon only;
// D  < x < DD : We see two data photons, no herald;
// DD < x      : We see herald and two data photons.
// This function initializes and draws from a uniform distribution.
// It is also used to generate uniform noise for the bs bits.
// We give two versions: One draw at a time in the continuous interval [0,1),
// And multiple coin flips packed in a vector.
// fn generate_uniform(trng: &mut Trng<'_>) -> f32 {    
//     let mut buffer: [u8;8] = [0;8]; // Init buffer
//     trng.read(&mut buffer);         // Read entropy from dedicated hw module
//     let seed = u64::from_be_bytes(buffer); // Glue buffer together to obtain seed
//     let mut rng = SmallRng::seed_from_u64(seed); // Seed random number generator
//     let result: f32 = rng.sample(StandardUniform); // Draw
//     return result;
// }

fn generate_uniform_vec(trng: &mut Trng<'_>, total_size : usize) -> Vec<f32> {    
    let mut buffer: [u8;8] = [0;8]; // Init buffer
    trng.read(&mut buffer);         // Read entropy from dedicated hw module
    let seed = u64::from_be_bytes(buffer); // Glue buffer together to obtain seed
    let rng = SmallRng::seed_from_u64(seed); // Seed random number generator
    let result: Vec<f32> = rng.sample_iter(StandardUniform).take(total_size).collect(); // Draw
    return result;
}

fn generate_uniform_coinflip(trng: &mut Trng<'_>, total_size : usize) -> Vec<u8> {    
    let mut buffer: [u8;8] = [0;8]; // Init buffer
    trng.read(&mut buffer);         // Read entropy from dedicated hw module
    let seed = u64::from_be_bytes(buffer); // Glue buffer together to obtain seed
    let mut rng = SmallRng::seed_from_u64(seed); // Seed random number generator
    let uniform_ranged: Uniform<u8> = Uniform::new_inclusive(0, 254).unwrap();
    let result: Vec<u8> = uniform_ranged.sample_iter(&mut rng).take(total_size).collect(); // Draw
    return result;
}

// Time delays between emission events follow a
// Normal distribution with mean DD_M and
// variance DD_DEV. Probability density:
//        _
//     _/||\_
//   _|||||||\_
//__/||||||||||\__
//  1   2   3   4
// This function initializes and draws from a normal distribution.
// We round to the nearest natural as this is ok in the orders we're working in.
// We give two versions: One draw at a time, and multiple draws packed in a vector.

// fn generate_normal(trng: &mut Trng<'_>, mean : f32, stdev: f32) -> u32 {    
//     let mut buffer: [u8;8] = [0;8]; // Init buffer
//     trng.read(&mut buffer);         // Read entropy from dedicated hw module
//     let seed = u64::from_be_bytes(buffer); // Glue buffer together to obtain seed
//     let mut rng = SmallRng::seed_from_u64(seed); // seed random number generator
//     let normal = Normal::new(mean, stdev).unwrap(); // Init normal distribution
//     let result: u32 = normal.sample(&mut rng) as u32; // Draw
//     return result;
// }

fn generate_normal_vec(
    trng        : &mut Trng<'_>,
    total_size  : usize, // Size in bits, not in bytes, since we're not crunching u8s out!
    mean        : f32,
    stdev       : f32) -> Vec<u32> {    
    let mut buffer: [u8;8] = [0;8]; // Init buffer
    trng.read(&mut buffer);         // Read entropy from dedicated hw module
    let seed = u64::from_be_bytes(buffer); // Glue buffer together to obtain seed
    let mut rng = SmallRng::seed_from_u64(seed); // seed random number generator
    let normal = Normal::new(mean, stdev).unwrap(); // Init normal distribution
    let result: Vec<u32> = normal.sample_iter(&mut rng).take(total_size).map(|x| {x as u32}).collect(); // Draw
    return result;
}

// Time delays between emission events follow a
// Normal distribution with mean DD_M and
// variance DD_DEV. 
//\      
//|\_    
//|||\_  
//|||||\__
//||||||||\_________
// This function initializes and draws from an exponential distribution.
// We give two versions: One draw at a time, and multiple draws packed in a vector.

// fn generate_exp(trng: &mut Trng<'_>, lambda : f32) -> u32 {    
//     let mut buffer: [u8;8] = [0;8]; // Init buffer
//     trng.read(&mut buffer);         // Read entropy from dedicated hw module
//     let seed = u64::from_be_bytes(buffer); // glue buffer together to obtain seed
//     let mut rng = SmallRng::seed_from_u64(seed); // seed random number generator
//     let exp = Exp::new(lambda).unwrap(); // Init exponential distribution
//     let result: u32 = exp.sample(&mut rng) as u32; // Draw
//     return result;
// }

fn generate_exp_vec(
    trng: &mut Trng<'_>,
    total_size  : usize, // Size in bits, not in bytes, since we're not crunching u8s out!
    lambda : f32
) -> Vec<u32> {    
    let mut buffer: [u8;8] = [0;8]; // Init buffer
    trng.read(&mut buffer);         // Read entropy from dedicated hw module
    let seed = u64::from_be_bytes(buffer); // glue buffer together to obtain seed
    let mut rng = SmallRng::seed_from_u64(seed); // seed random number generator
    let exp = Exp::new(lambda).unwrap(); // Init exponential distribution
    let result: Vec<u32> = exp.sample_iter(&mut rng).take(total_size).map(|x| {x as u32}).collect(); // Draw
    return result;
}


// PULSE TRIGGERS //

// Triggers pulse on herald.
// Returns the length of the pulse.
fn fire_herald (herald : &mut Output<'_>, delay: Delay) -> u32 {
    herald.set_high();
    delay.delay_micros(PULSE_WIDTH);
    herald.set_low();
    return PULSE_WIDTH;
}

// Triggers pulse on outcome0 or outcome1 pin depending on value.
// Returns the length of the pulse.
fn fire_outcomei(
    outcome0 : &mut Output<'_>,
    outcome1 : &mut Output<'_>, 
    delay    : Delay,
    value    : bool
) -> u32 {
    if !value {
        outcome0.set_high();
        delay.delay_micros(PULSE_WIDTH);
        outcome0.set_low();
    } else {
        outcome1.set_high();
        delay.delay_micros(PULSE_WIDTH);
        outcome1.set_low();
    }
    return PULSE_WIDTH;
}


// REAL CASE EMISSION EVENTS //

// Simulates how the QKD detector spits out data.
// A data emission is consider an 'event', which is defined
// In the next function.
// An event happens randomly: It may not happen at all, or
// Happen multiple times. We limit ourselves to 2, but in the real case it may be more than that.
// In the ideal case, we expect exactly one event being detected
// Within the admissable detection window.
fn fire_real(
    outcome0    : &mut Output<'_>,
    outcome1    : &mut Output<'_>, 
    herald      : &mut Output<'_>,
    delay       : Delay,
    value       : bool,
    rn_uniform  : f32, // Determines the type of event observed
    rn_normal1   : u32, // Determines the delay
    rn_normal2   : u32, // Determines the delay
    rn_exp1      : u32, // Determines 
    rn_exp2      : u32, // Determines 
) {
    if rn_exp1 < REAL_DELAY_TIME{ // We got our first emission event
        delay.delay_micros(rn_exp1);
        if random_emission_event(
            outcome0, outcome1, herald, delay,
            value, rn_uniform, rn_normal1, rn_normal2)
        + rn_exp2 < REAL_DELAY_TIME { // We got time for another one!
                random_emission_event(
                    outcome0, outcome1, herald, delay,
                    value, rn_uniform, rn_normal1, rn_normal2
                );
            }
    }
}

// This simulates a real emission event, where many things can happen, such as:
// Heralding photon and data photon are seen (ideal case), or
// Only heralding photon is seen, or
// Only data photon is seen, or
// Both data photons are seen, or
// Both data photons and herald are seen.
// Moreover, delay times between these events are randomly drawn from a normal distribution.
fn random_emission_event(
    outcome0    : &mut Output<'_>,
    outcome1    : &mut Output<'_>, 
    herald      : &mut Output<'_>,
    delay       : Delay,
    value       : bool,
    rn_uniform  : f32, // Determines the type of event observed
    rn_normal1  : u32, // Determines the delay
    rn_normal2  : u32, // Determines the delay
) -> u32 {
    if rn_uniform < HD        { // Herald and data
        let herald_time = fire_herald(herald, delay);
        delay.delay_micros(rn_normal1);
        return herald_time + rn_normal1 + fire_outcomei(outcome0, outcome1, delay, value);
    } else if rn_uniform < H  { // Only Herald
        return fire_herald(herald, delay);
    } else if rn_uniform < D  { // Only Data
        delay.delay_micros(rn_normal1);
        return rn_normal1 + fire_outcomei(outcome0, outcome1, delay, value);
    } else if rn_uniform < DD { // Only two data photons
        if rn_normal1 < rn_normal2 {
            delay.delay_micros(rn_normal1);
            fire_outcomei(outcome0, outcome1, delay, false);
            delay.delay_micros(rn_normal2 - rn_normal1);
            return rn_normal2 + 2*fire_outcomei(outcome0, outcome1, delay, true);
        } else {
            delay.delay_micros(rn_normal2);
            fire_outcomei(outcome0, outcome1, delay, true);
            delay.delay_micros(rn_normal1 - rn_normal2);
            return rn_normal2 + 2*fire_outcomei(outcome0, outcome1, delay, false);
        }
    } else                    { // Herald and two data photons
        let herald_time = fire_herald(herald, delay);
        if rn_normal1 < rn_normal2 {
            delay.delay_micros(rn_normal1);
            fire_outcomei(outcome0, outcome1, delay, false);
            delay.delay_micros(rn_normal2 - rn_normal1);
            return herald_time + rn_normal2 + 2*fire_outcomei(outcome0, outcome1, delay, true);
        } else {
            delay.delay_micros(rn_normal2);
            fire_outcomei(outcome0, outcome1, delay, true);
            delay.delay_micros(rn_normal1 - rn_normal2);
            return herald_time + rn_normal2 + 2*fire_outcomei(outcome0, outcome1, delay, false);
        }
    }
}