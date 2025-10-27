// Developed for ESP32
// Tested on Adafruit HUZZAH32

// == Type Aliases ==
typedef bool bit;
typedef unsigned long time_us; // A non-negative time value in microseconds
typedef uint16_t length_t;     // Type used for lengths of arrays

// == Output Pins on ESP32 ==
#define RUNNING_PIN 32      // Set to HIGH to start the generator, set to LOW to stop.
#define BASIS_SELECT_PIN 14 // Tells the generator which basis is being measured by the TEE.

// == Input Pins on ESP32 ==
#define RECEIVING_PIN 12 // Set to HIGH when generator starts sending data, set to LOW when generator goes idle.
#define HERALD_PIN 27    // Pulsed to HIGH when herald detector is triggered.
#define OUTCOME0_PIN 33  // Pulsed to HIGH when outcome 0 detector is triggered.
#define OUTCOME1_PIN 15  // Pulsed to HIGH when outcome 1 detector is triggered.

// == Shared Constants ==
#define OUTCOME_DELAY_US 500
#define OUTCOME_DELAY_STDDEV_US 50
#define HASH_NUM_BITS 64
#define HASH_NUM_BYTES HASH_NUM_BITS / 8

// == Local Constants ==
#define MIN_OUTCOME_DELAY_US OUTCOME_DELAY_US - 3 * OUTCOME_DELAY_STDDEV_US
#define MAX_OUTCOME_DELAY_US OUTCOME_DELAY_US + 3 * OUTCOME_DELAY_STDDEV_US

// == Flags ==
#define DEBUG true
#define DISPLAY true

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
  bits[idx / 8] &= ~mask;
  bits[idx / 8] |= value * mask;
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
 * Packed bitvector containing the location of the Z-encoded bit in each bit pair:
 * - read_bit(received, 2*j+read_bit(order, j)) must match read_bit(table_row_z, j)
 * - read_bit(received, 2*j+!read_bit(order, j)) must match read_bit(table_row_x, j)
 */
uint8_t const order[HASH_NUM_BYTES] = {0x61, 0x2b, 0x1f, 0xce, 0x77, 0xc8, 0x69, 0x34};

// == State Variables ==
volatile length_t cycle = 0;
volatile bool receiving = false;
volatile bool herald_seen = false;
volatile bool herald_locked = false;
volatile time_us herald_time = 0;
volatile bool outcome0_seen = false;
volatile bool outcome1_seen = false;
volatile uint8_t received[2 * HASH_NUM_BYTES] = {0};
volatile uint8_t received_success[2 * HASH_NUM_BYTES] = {0};
uint8_t hash[HASH_NUM_BYTES] = {0};

#if DEBUG
// == Debug State Variables ==
volatile time_us _cycle_time[2 * HASH_NUM_BITS] = {0};
volatile bool _herald_seen[2 * HASH_NUM_BITS] = {false};
volatile time_us _herald_time[2 * HASH_NUM_BITS] = {0};
volatile bool _outcome0_seen[2 * HASH_NUM_BITS] = {false};
volatile bool _outcome1_seen[2 * HASH_NUM_BITS] = {false};
volatile time_us _outcome0_delay[2 * HASH_NUM_BITS] = {0};
volatile time_us _outcome1_delay[2 * HASH_NUM_BITS] = {0};
#endif

// Interrupts are only kept attached while bitstream is being received.
FORCE_INLINE void attachInterrupts();
FORCE_INLINE void detachInterrupts();

/**
 * Sets the hash, the bits of which are used to select the measurement basis for each subsequent even-odd cycle pair.
 * qubits at cycles 2*j and 2*j+1 are measured in the Z basis if if read_bit(hash, j) is 0 and in the X basis otherwise.
 */
void set_hash()
{
  // In this prototype, we set the hash to a fixed value, so the same procecss is repeated at each run.
  static uint8_t const temp[8] = {0x5b, 0xfc, 0x94, 0xc7, 0x58, 0x94, 0xed, 0xd3};
  memcpy(hash, temp, sizeof(hash));
}

/**
 * Starts the bitstream from the generator.
 */
FORCE_INLINE
void start_bitstream()
{
  cycle = 0;
  attachInterrupts();
  digitalWrite(BASIS_SELECT_PIN, read_bit(hash, 0));
  digitalWrite(RUNNING_PIN, HIGH);
}

/**
 * Stops the bitstream from the generator.
 */
FORCE_INLINE
void stop_bistream()
{
  digitalWrite(RUNNING_PIN, LOW);
  detachInterrupts();
  cycle = 2 * HASH_NUM_BITS;
}

/**
 * Starts a new bit reception cycle.
 *
 * A cycle is the period during which the TEE expects to receive a single bit of data from the generator,
 * although in reality the process is noisy and the bit may not be received correctly.
 */
FORCE_INLINE
void start_cycle()
{
#if DEBUG
  _cycle_time[cycle] = micros();
  _herald_seen[cycle] = false;
  _herald_time[cycle] = 0;
  _outcome0_seen[cycle] = false;
  _outcome1_seen[cycle] = false;
  _outcome0_delay[cycle] = 0;
  _outcome1_delay[cycle] = 0;
#endif
  herald_seen = false;
  herald_locked = false;
  outcome0_seen = false;
  outcome1_seen = false;
  receiving = true;
}

/**
 * Stops the current bit reception cycle.
 *
 * A cycle is the period during which the TEE expects to receive a single bit of data from the generator,
 * although in reality the process is noisy and the bit may not be received correctly.
 */
FORCE_INLINE
void stop_cycle()
{
  receiving = false;
  if (herald_seen && (outcome0_seen ^ outcome1_seen))
  {
    write_bit(received, cycle, outcome1_seen);
    write_bit(received_success, cycle, 1);
  }
  else
  {
    write_bit(received_success, cycle, 0);
  }
  cycle += 1;
  if (cycle % 2 == 0)
    digitalWrite(BASIS_SELECT_PIN, read_bit(hash, cycle / 2));
}

/**
 * Starts and stops a single cycle, depending on whether RECEIVING_PIN is rising or falling, resp.
 */
void IRAM_ATTR start_and_stop_cycle()
{
  if (cycle == 2 * HASH_NUM_BITS)
    stop_bistream();
  else if (digitalRead(RECEIVING_PIN) == HIGH)
    start_cycle();
  else
    stop_cycle();
}

/**
 * Records that a herald photon has been observed in this bit reception cycle.
 *
 * Observation of a herald photon pre-empts the potential observation of a data photon, but it is not
 * necessarily the case that the first herald photon observed is one which will be followed by a data photon.
 * As a consequence, the time of herald photon observation is updated at each observation, until the first
 * data photon is received (at which point the herald photon time is locked).
 */
void IRAM_ATTR see_herald()
{
  if (!receiving || herald_locked)
    return;
  herald_time = micros();
  herald_seen = true;
#if DEBUG
  _herald_seen[cycle] = true;
  _herald_time[cycle] = herald_time;
#endif
}

/**
 * Records that a data photon has been measured with outcome 0 in this bit reception cycle.
 *
 * Measurement of a data photon is only recorded if it happens after observation of a herald photon,
 * within a pre-defined time window based on the time delays expected from the quantum HW setup.
 */
void IRAM_ATTR see_outcome0()
{
  if (!receiving || !herald_seen)
    return;
  time_us delay = micros() - herald_time;
  if (delay >= MIN_OUTCOME_DELAY_US && delay <= MAX_OUTCOME_DELAY_US)
  {
    herald_locked = true;
    outcome0_seen = true;
#if DEBUG
    _outcome0_seen[cycle] = true;
    _outcome0_delay[cycle] = delay;
#endif
  }
}

/**
 * Records that a data photon has been measured with outcome 1 in this bit reception cycle.
 *
 * Measurement of a data photon is only recorded if it happens after observation of a herald photon,
 * within a pre-defined time window based on the time delays expected from the quantum HW setup.
 */
void IRAM_ATTR see_outcome1()
{
  if (!receiving || !herald_seen)
    return;
  time_us delay = micros() - herald_time;
  if (delay >= MIN_OUTCOME_DELAY_US && delay <= MAX_OUTCOME_DELAY_US)
  {
    herald_locked = true;
    outcome1_seen = true;
#if DEBUG
    _outcome1_seen[cycle] = true;
    _outcome1_delay[cycle] = delay;
#endif
  }
}

/**
 * Checks correct reception the data bitstream.
 * Writes whether each bit is correct or not onto the given output bitstream.
 */
void check_correctness(uint8_t out[HASH_NUM_BYTES])
{
  for (length_t i = 0; i < HASH_NUM_BITS; i++)
  {
    bit hash_bit = read_bit(hash, i);
    uint8_t const* row = hash_bit == 0 ? table_row_z : table_row_x;
    length_t cycle = 2 * i + hash_bit ^ read_bit(order, i);
    write_bit(out, i, read_bit(received_success, cycle) && read_bit(row, i) == read_bit(received, cycle));
  }
}

#if DISPLAY
#include <Wire.h>
#include <Adafruit_GFX.h>
#include "Adafruit_LEDBackpack.h"

Adafruit_8x8matrix matrix = Adafruit_8x8matrix();

void display_success()
{
  uint8_t correct_bits[8] = {0};
  check_correctness(correct_bits);
  matrix.clear();
  matrix.drawBitmap(0, 0, correct_bits, 8, 8, LED_ON);
  matrix.writeDisplay();
}
#endif

#if DEBUG
template <typename T>
length_t count(volatile T const* b, T value, length_t len)
{
  length_t count = 0;
  for (length_t i = 0; i < len; i++)
  {
    if (b[i] == value)
      count += 1;
  }
  return count;
}

template <typename T>
float mean(volatile T const* a, length_t len)
{
  if (len == 0)
    return 0.0;
  float mean = 0;
  for (length_t i = 0; i < len; i++)
    mean += a[i];
  return mean / len;
}

template <typename T>
float mean_if(volatile T const* a, volatile bool const* b, length_t len)
{
  float mean = 0;
  length_t count = 0;
  for (length_t i = 0; i < len; i++)
  {
    if (b[i])
    {
      mean += a[i];
      count += 1;
    }
  }
  if (count == 0)
    return 0.0;
  return mean / count;
}

template <typename T>
float sdev(volatile T const* a, float m, length_t len)
{
  if (len == 0)
    return 0.0;
  float sdev = 0;
  for (length_t i = 0; i < len; i++)
    sdev += (a[i] - m) * (a[i] - m);
  return sqrt(sdev / len);
}

template <typename T>
float sdev_if(volatile T const* a, volatile bool const* b, float m, length_t len)
{
  float sdev = 0;
  length_t count = 0;
  for (length_t i = 0; i < len; i++)
  {
    float d = (a[i] - m);
    if (b[i])
    {
      sdev += d * d;
      count += 1;
    }
  }
  if (count == 0)
    return 0.0;
  return sqrt(sdev / count);
}

void print_debug_info()
{
  time_us _cycle_time_delta[2 * HASH_NUM_BITS - 1] = {0};
  for (length_t cycle = 0; cycle < 2 * HASH_NUM_BITS - 1; cycle++)
    _cycle_time_delta[cycle] = _cycle_time[cycle + 1] - _cycle_time[cycle];
  time_us _herald_time_delta[2 * HASH_NUM_BITS] = {0};
  for (length_t cycle = 0; cycle < 2 * HASH_NUM_BITS; cycle++)
    _herald_time_delta[cycle] = _herald_time[cycle] - _cycle_time[cycle];
  float _herald_obs_prob = count(_herald_seen, true, 2 * HASH_NUM_BITS) / ((float)2 * HASH_NUM_BITS);
  float _outcome0_obs_prob = count(_outcome0_seen, true, 2 * HASH_NUM_BITS) / ((float)2 * HASH_NUM_BITS);
  float _outcome1_obs_prob = count(_outcome1_seen, true, 2 * HASH_NUM_BITS) / ((float)2 * HASH_NUM_BITS);
  float _cycle_time_delta_mean = mean(_cycle_time_delta, 2 * HASH_NUM_BITS - 1);
  float _herald_time_mean = mean_if(_herald_time_delta, _herald_seen, 2 * HASH_NUM_BITS);
  float _outcome0_delay_mean = mean_if(_outcome0_delay, _outcome0_seen, 2 * HASH_NUM_BITS);
  float _outcome1_delay_mean = mean_if(_outcome1_delay, _outcome1_seen, 2 * HASH_NUM_BITS);
  float _cycle_time_delta_stddev = sdev(_cycle_time_delta, _cycle_time_delta_mean, 2 * HASH_NUM_BITS - 1);
  float _herald_time_stddev = sdev_if(_herald_time_delta, _herald_seen, _herald_time_mean, 2 * HASH_NUM_BITS);
  float _outcome0_delay_stddev = sdev_if(_outcome0_delay, _outcome0_seen, _outcome0_delay_mean, 2 * HASH_NUM_BITS);
  float _outcome1_delay_stddev = sdev_if(_outcome1_delay, _outcome1_seen, _outcome1_delay_mean, 2 * HASH_NUM_BITS);
  Serial.printf("Herald obs probability: %.1f%%\n", 100 * _herald_obs_prob);
  Serial.printf("Outcome 0 obs probability: %.1f%%\n", 100 * _outcome0_obs_prob);
  Serial.printf("Outcome 1 obs probability: %.1f%%\n", 100 * _outcome1_obs_prob);
  Serial.printf("Cycle time: %.0fus (stddev: %.0fus)\n", _cycle_time_delta_mean, _cycle_time_delta_stddev);
  Serial.printf("Herald time: %.0fus (stddev: %.0fus)\n", _herald_time_mean, _herald_time_stddev);
  Serial.printf("Outcome 0 delay: %.0fus (stddev: %.0fus)\n", _outcome0_delay_mean, _outcome0_delay_stddev);
  Serial.printf("Outcome 1 delay: %.0fus (stddev: %.0fus)\n", _outcome1_delay_mean, _outcome1_delay_stddev);
  Serial.println();
}
#endif

// == Main Loop Logic ==

FORCE_INLINE
void attachInterrupts()
{
  attachInterrupt(RECEIVING_PIN, start_and_stop_cycle, CHANGE);
  attachInterrupt(HERALD_PIN, see_herald, RISING);
  attachInterrupt(OUTCOME0_PIN, see_outcome0, RISING);
  attachInterrupt(OUTCOME1_PIN, see_outcome1, RISING);
}

FORCE_INLINE
void detachInterrupts()
{
  detachInterrupt(RECEIVING_PIN);
  detachInterrupt(HERALD_PIN);
  detachInterrupt(OUTCOME0_PIN);
  detachInterrupt(OUTCOME1_PIN);
}

void setup()
{
  pinMode(RUNNING_PIN, OUTPUT);
  pinMode(BASIS_SELECT_PIN, OUTPUT);
  pinMode(RECEIVING_PIN, INPUT);
  pinMode(HERALD_PIN, INPUT);
  pinMode(OUTCOME0_PIN, INPUT);
  pinMode(OUTCOME1_PIN, INPUT);
#if DISPLAY
  matrix.begin(0x70);
#endif
#if DEBUG
  Serial.begin(115200);
  Serial.println("Started bistream.");
#endif
  set_hash();
  start_bitstream();
}

void loop()
{
  // 1. Loop while bitstream is being received:
  if (cycle < 2 * HASH_NUM_BITS)
    return;
// 2. Use the bitstream (here, debug and/or display):
#if DEBUG
  Serial.println("Stopped bitstream.");
#endif
#if DISPLAY
  display_success();
#endif
#if DEBUG
  print_debug_info();
#else
  delay(100);
#endif
// 3. Start the bistream reception process again:
#if DEBUG
  Serial.println("Restarted bitstream.");
#endif
  set_hash();
  start_bitstream();
}
