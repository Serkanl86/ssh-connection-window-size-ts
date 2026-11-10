import test from 'node:test';
import assert from 'node:assert/strict';
import {
  WindowAdjustError,
  WindowTracker,
  parseWindowAdjust,
  encodeWindowAdjust,
} from '../src/index.js';

function bytes(...values) {
  return Uint8Array.from(values);
}

test('parses a canonical window-adjust payload', () => {
  const payload = bytes(93, 0, 0, 0, 7, 0, 0, 16, 0);
  const parsed = parseWindowAdjust(payload);
  assert.deepEqual(parsed, { recipientChannel: 7, windowSize: 4096 });
});

test('parses a payload without the type byte when told to', () => {
  const payload = bytes(0, 0, 0, 3, 0, 0, 0, 255);
  const parsed = parseWindowAdjust(payload, { hasTypeByte: false });
  assert.deepEqual(parsed, { recipientChannel: 3, windowSize: 255 });
});

test('rejects a payload with the wrong message type', () => {
  const payload = bytes(94, 0, 0, 0, 1, 0, 0, 0, 1);
  assert.throws(() => parseWindowAdjust(payload), WindowAdjustError);
});

test('rejects a truncated payload', () => {
  const payload = bytes(93, 0, 0, 0, 1, 0, 0);
  assert.throws(() => parseWindowAdjust(payload), WindowAdjustError);
});

test('rejects a non-Uint8Array payload', () => {
  assert.throws(() => parseWindowAdjust([93, 0, 0, 0, 1, 0, 0, 0, 1]), WindowAdjustError);
});

test('encodes and round-trips a window-adjust payload', () => {
  const encoded = encodeWindowAdjust(42, 123456);
  assert.equal(encoded.length, 9);
  assert.deepEqual(parseWindowAdjust(encoded), { recipientChannel: 42, windowSize: 123456 });
});

test('encodes without the type byte when asked', () => {
  const encoded = encodeWindowAdjust(1, 2, { includeTypeByte: false });
  assert.equal(encoded.length, 8);
  assert.deepEqual(parseWindowAdjust(encoded, { hasTypeByte: false }), {
    recipientChannel: 1,
    windowSize: 2,
  });
});

test('rejects out-of-range encode arguments', () => {
  assert.throws(() => encodeWindowAdjust(-1, 0), WindowAdjustError);
  assert.throws(() => encodeWindowAdjust(0, 0x100000000), WindowAdjustError);
  assert.throws(() => encodeWindowAdjust(0.5, 0), WindowAdjustError);
});

test('tracker accumulates window adjustments', () => {
  const tracker = new WindowTracker(10);
  assert.equal(tracker.apply({ recipientChannel: 0, windowSize: 5 }), 15);
  assert.equal(tracker.apply({ recipientChannel: 0, windowSize: 0 }), 15);
});

test('tracker consumes bytes and refuses over-consumption', () => {
  const tracker = new WindowTracker(100);
  assert.equal(tracker.consume(40), 60);
  assert.throws(() => tracker.consume(61), WindowAdjustError);
  assert.equal(tracker.window, 60);
});

test('tracker rejects negative or non-integer values', () => {
  const tracker = new WindowTracker(10);
  assert.throws(() => tracker.apply({ recipientChannel: 0, windowSize: -1 }), WindowAdjustError);
  assert.throws(() => tracker.consume(-1), WindowAdjustError);
  assert.throws(() => tracker.consume(1.5), WindowAdjustError);
});

test('tracker constructor rejects invalid initial windows', () => {
  assert.throws(() => new WindowTracker(-1), WindowAdjustError);
  assert.throws(() => new WindowTracker(1.5), WindowAdjustError);
});

test('tracker guards against window overflow', () => {
  const tracker = new WindowTracker(Number.MAX_SAFE_INTEGER - 1);
  assert.throws(() => tracker.apply({ recipientChannel: 0, windowSize: 2 }), WindowAdjustError);
});
