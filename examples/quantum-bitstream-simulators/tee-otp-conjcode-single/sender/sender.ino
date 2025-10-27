// Developed for ATmega328p
// Tested on Adafruit Pro Trinket 3.3V (12MHz)

#include <stdlib.h>
#include <stdint.h>
#include <math.h>

// == Type Aliases and Constants ==
typedef bool bit;
typedef unsigned long time_us; // A non-negative time value in microseconds
typedef uint16_t length_t;     // Type used for lengths of arrays
typedef bit basis;             // Qubit basis choice: 0 for Z, 1 for X

// == Use Analog Tuner ==
// If set to true, analog read from a designated pin is used to interpolate
// between the ideal emission case (pin input at highest value) and the
// realistic emission case from Thor Labs specs (pin input at lowest value).
#define USE_TUNER true

// == Analog Input Pins on ATmega328p ==
#if USE_TUNER
#define TUNER_PIN 14
#endif

// == Input Pins on ATmega328p ==
#define RUNNING_PIN 3
#define BASIS_SELECT_PIN 9

// == Output Pins on ATmega328p ==
#define SENDING_PIN 4
#define HERALD_PIN 5
#define OUTCOME0_PIN 6
#define OUTCOME1_PIN 8

// == Correlated Photon-Pair Source Data ==
// See single-photon output specs for SPDC810 by Thor Labs:
// https://www.thorlabs.com/newgrouppage9.cfm?objectgroup_id=13675
#define _SPDC810_H 130796
#define _SPDC810_1 45376
#define _SPDC810_2 55128
#define _SPDC810_H1 15229
#define _SPDC810_H2 17435
#define _SPDC810_H12 8
#define _SPDC810_12 24              // approximated from data above
#define _SPDC810_EVENT_COUNT 263972 // sum of all above

// == Event Probabilities ==
#define P_HD 0.12371  // Heralded data
#define P_H 0.49546   // Heralding only
#define P_D 0.38071   // Data only
#define P_DD 0.00009  // Spurious double data (no heralding)
#define P_HDD 0.00003 // Spurious double data (heralding)

// == Simplified Event Probabilities (Ideal case) ==
// #define P_HD  1.0 // Heralded data
// #define P_H   0.0 // Heralding only
// #define P_D   0.0 // Data only
// #define P_DD  0.0 // Spurious double data (no heralding)
// #define P_HDD 0.0 // Spurious double data (heralding)

// == Cumulative Event Probabilities ==
#if USE_TUNER
float CP_HD = P_HD;
float CP_H = P_H + CP_HD;
float CP_D = P_D + CP_H;
float CP_DD = P_DD + CP_D;
#else
#define CP_HD P_HD
#define CP_H P_H + CP_HD
#define CP_D P_D + CP_H
#define CP_DD P_DD + CP_D
#endif

// == Emission Rate (events/us) ==
// In reality, this would be ~250kHz, but here we slow things down for testing purposes.
#define EMISSION_RATE_US 1 / 1000.0 // 1/1000 per us = 1 per ms = 1kHz

// == Enable Time (in us) ==
// The time where we expect exactly one data photon emission, regardless of whether it is heralded or not.
// This is because any additional data photon going through could, in principle, be used to learn the secret bit.
#define ENABLE_TIME_US (time_us)1 / (EMISSION_RATE_US * (P_D + P_HD)) // ~2ms

// == Idle Time (in us) ==
// The time during data photons are shuttered while the bit/basis selection switches change position.
// In reality, this has to be to >1ms.
#define IDLE_TIME_US 2000

// == Pulse Width (in us) ==
// The width of the signal pulses, broadened for testing purposes.
// In reality, this would come from the single photon detectors, with pulse widths between 10ns-20ns.
// We will need to stretch this (e.g. with low-pass RC filter + diodes) for ESP32 interrupts to trigger.
// See specs for SPDMH2F by Thor Labs:
// https://www.thorlabs.com/newgrouppage9.cfm?objectgroup_id=5255&pn=SPDMH2F
#define PULSE_WIDTH 20

// == Mean Data Delay (in us) ==
// The mean delay of the data photon compared to the herald photon.
// This depends on the circuitry traversed by the data photon.
// In reality, this will be in the 10s of ns, but here we slow things down so the ATmega328p can cope.
// See single-photon output specs for SPDC810 by Thor Labs:
// https://www.thorlabs.com/newgrouppage9.cfm?objectgroup_id=13675
#define DATA_DELAY_US 500

// == Data Delay Std Dev (in us) ==
// The standard deviation of the data photon delay.
// In reality this is ~1ns, but here we slow things down proportionally to DATA_DELAY_US.
// See single-photon output specs for SPDC810 by Thor Labs:
// https://www.thorlabs.com/newgrouppage9.cfm?objectgroup_id=13675
#define DATA_DELAY_STDDEV_US 50

// == Hash and Secret Table Sizes ==
#define HASH_NUM_BITS 64
#define HASH_NUM_BYTES HASH_NUM_BITS / 8

#define FORCE_INLINE inline __attribute__((always_inline))

/** Reads a from a packed bitvector. */
FORCE_INLINE
bit read_bit(volatile uint8_t const* bits, length_t idx)
{
  return (bool)(bits[idx / 8] & (1 << 7 - idx % 8));
}

/** Writes a bit onto a packed bitvector. */
FORCE_INLINE
void write_bit(volatile uint8_t* bits, length_t idx, bit value)
{
  uint8_t mask = (1 << 7 - idx % 8);
  if (value)
    bits[idx / 8] |= mask;
  else
    bits[idx / 8] &= ~mask;
}

/** Cheap generation of uniformly distributed float in [0, 1) */
float rand_uniform()
{
  uint16_t x = (uint16_t)(micros() % 65536);
  x = ((x >> 8) ^ x) * 0x5BD1;
  x = (x >> 8) ^ x;
  return x / 65536.0;
}

/**
 * Cheap generation of normally distributed float with given mean and stddev,
 * approximated by
 */
float rand_normal(float mean, float stddev)
{
  float u1 = rand_uniform();
  float u2 = rand_uniform();
  float z0 = (u1 + u2 - 1.0) * 2.44948974278;
  //                   sqrt(6) ^^^^^^^^^^^^^
  return mean + stddev * z0;
}

/**
 * Cheap generation of exponentially distributed float with given rate,
 * approximated by a 5th order tailor expansion of -log(1.0-rand_uniform())/lambda
 */
float rand_exp(float lambda)
{
  float u = rand_uniform();
  float u2 = u * u;
  float u3 = u2 * u;
  // float y = u + 0.5f * u2 + 0.333333f * u3 + 0.25 * u2*u2 + 0.2 * u3*u2;
  float y = 3 * u - 22 * u2 + 80.5 * u3 - 113 * u2 * u2 + 55.5 * u3 * u2;
  return y / lambda;
}

/**
 * Packed bitvector containing the 64 secret bits in the Z row of the TEE table.
 */
uint8_t const table_row_z[HASH_NUM_BYTES] = {0x31, 0x5f, 0x5b, 0xdb, 0x76, 0xd0, 0x78, 0xc4};

/**
 * Packed bitvector containing the 64 secret bits in the X row of the TEE table.
 */
uint8_t const table_row_x[HASH_NUM_BYTES] = {0x3b, 0x8a, 0xc0, 0x06, 0x4e, 0x4a, 0x01, 0x64};

/**
 * Packed bitvector containing the location of the Z-encoded bit in each bit pair.
 */
uint8_t const order[HASH_NUM_BYTES] = {0x61, 0x2b, 0x1f, 0xce, 0x77, 0xc8, 0x69, 0x34};

// == State Variables ==
length_t cycle = 0;
bool running = false;

/** Starts the bitstream sent to the TEE. */
void start_bitstream()
{
  cycle = 0;
#if USE_TUNER
  // Read analog input from tuner pin:
  float _p = analogRead(TUNER_PIN) / 1023.0;
  float _q = 1.0 - _p;
  // Tune cumulative event probabilities:
  CP_HD = _q * P_HD + _p;
  CP_H = _q * P_H + CP_HD;
  CP_D = _q * P_D + CP_H;
  CP_DD = _q * P_DD + CP_D;
#endif
  running = true;
  digitalWrite(LED_BUILTIN, HIGH);
}

/** Stops the bitstream sent to the TEE. */
void stop_bitstream()
{
  running = false;
  digitalWrite(LED_BUILTIN, LOW);
}

/**
 * Generates a pulse mimicking the detection of a herald photon.
 */
FORCE_INLINE
void pulse_herald()
{
  digitalWrite(HERALD_PIN, HIGH);
  delayMicroseconds(PULSE_WIDTH);
  digitalWrite(HERALD_PIN, LOW);
}

/**
 * Generates a pulse mimicking the detection of a data photon for the given outcome.
 */
FORCE_INLINE
void pulse_data(bit outcome)
{
  int outcome_pin = outcome == 0 ? OUTCOME0_PIN : OUTCOME1_PIN;
  digitalWrite(outcome_pin, HIGH);
  delayMicroseconds(PULSE_WIDTH);
  digitalWrite(outcome_pin, LOW);
}

/**
 * Generates a pulse mimicking the detection of a data photon with the given bit value encoded,
 * including time delay (from herald photon detection) and accounting for the possible mismatch between
 * the measurement basis choice on the TEE side and the encoding basis choice on the generator side
 * (in which case the detected outcome is selected randomly, with 50-50 probability).
 */
FORCE_INLINE
void pulse_delayed_data(bit value, basis encoding_basis, basis measurement_basis)
{
  float delay = max(rand_normal(DATA_DELAY_US, DATA_DELAY_STDDEV_US * 0.9) - 275.0, 0.0);
  delayMicroseconds(delay);
  if (encoding_basis == measurement_basis)
  {
    pulse_data(value);
  }
  else
  {
    if (rand_uniform() < 0.5)
      pulse_data(0);
    else
      pulse_data(1);
  }
}

/**
 * Generates a pulse mimicking the anomalous detection of photons on both outcomes,
 * including time delay (from herald photon detection) for both outcomes, in random order.
 */
FORCE_INLINE
void pulse_delayed_data_pair()
{
  time_us delay0 = rand_normal(DATA_DELAY_US, DATA_DELAY_STDDEV_US);
  time_us delay1 = rand_normal(DATA_DELAY_US, DATA_DELAY_STDDEV_US);
  if (delay0 >= delay1)
  {
    delayMicroseconds(delay1);
    pulse_data(1);
    delayMicroseconds(delay0 - delay1);
    pulse_data(0);
  }
  else
  {
    delayMicroseconds(delay0);
    pulse_data(0);
    delayMicroseconds(delay1 - delay0);
    pulse_data(1);
  }
}

/** Performs a random emission event. */
FORCE_INLINE
void random_emission_event(bit data_bit, basis encoding_basis, basis measurement_basis)
{
  float r = rand_uniform();
  if (r < CP_HD)
  { // Heralid Photon + Data Photon
    pulse_herald();
    pulse_delayed_data(data_bit, encoding_basis, measurement_basis);
  }
  else if (r < CP_H)
  { // Herald Photon Only
    pulse_herald();
  }
  else if (r < CP_D)
  { // Data Photon Only
    pulse_delayed_data(data_bit, encoding_basis, measurement_basis);
  }
  else if (r < CP_DD)
  { // Double Data Photon
    pulse_delayed_data_pair();
  }
  else
  { // Heralding Photon + Double Data Photon
    pulse_herald();
    pulse_delayed_data_pair();
  }
}

/** Performs a number of randomly timed random emission events. */
FORCE_INLINE
void emit_photons(bit data_bit, basis encoding_basis, basis measurement_basis)
{
  time_us cycle_start = micros();
  time_us t_emission = cycle_start + rand_exp(EMISSION_RATE_US);
  while (t_emission < cycle_start + ENABLE_TIME_US)
  {
    time_us _t = micros();
    if (t_emission > _t)
      delayMicroseconds(t_emission - _t);
    random_emission_event(data_bit, encoding_basis, measurement_basis);
    t_emission += rand_exp(EMISSION_RATE_US);
  }
  time_us time_elapsed = micros() - cycle_start;
  if (time_elapsed < ENABLE_TIME_US)
    delayMicroseconds(ENABLE_TIME_US - time_elapsed);
}

/** Runs a full cycle, over which a single data bit is transmitted, with a single basis choice. */
void run_cycle()
{
  bit encoding_basis = read_bit(order, cycle / 2) ^ (cycle % 2);
  uint8_t const* row = encoding_basis == 0 ? table_row_z : table_row_x;
  bit data_bit = read_bit(row, cycle / 2);
  bit measurement_basis = digitalRead(BASIS_SELECT_PIN);
  digitalWrite(SENDING_PIN, HIGH);
  emit_photons(data_bit, encoding_basis, measurement_basis);
  digitalWrite(SENDING_PIN, LOW);
  cycle += 1;
}

void setup()
{
  pinMode(RUNNING_PIN, INPUT);
  pinMode(BASIS_SELECT_PIN, INPUT);
  pinMode(SENDING_PIN, OUTPUT);
  pinMode(HERALD_PIN, OUTPUT);
  pinMode(OUTCOME0_PIN, OUTPUT);
  pinMode(OUTCOME1_PIN, OUTPUT);
}

/** Updates running status by checking the value of RUNNING_PIN at the start of each loop. */
FORCE_INLINE
void update_running()
{
  bool should_be_running = digitalRead(RUNNING_PIN);
  if (!running && should_be_running)
    start_bitstream();
  else if (running && !should_be_running)
    stop_bitstream();
}

void loop()
{
  update_running();
  if (running)
  {
    run_cycle();                          // Attempt to transmit one bit of data
    delayMicroseconds(IDLE_TIME_US - 30); // Idle while switches change position
  }
  else
    delay(200);
}
