const WINDOW_ADJUST_TYPE = 93;

/**
 * SSH channel window adjustment payload layout (RFC 4254 section 5.2):
 *
 *   byte      SSH_MSG_CHANNEL_WINDOW_ADJUST (93)
 *   uint32    recipient channel
 *   uint32    bytes to add to window
 *
 * The window size is an unsigned 32-bit value measured in bytes. We keep it
 * as a JavaScript number and reject anything that would exceed
 * Number.MAX_SAFE_INTEGER, though a uint32 can never reach that bound. The
 * guard exists so callers get a clear error instead of silent precision loss
 * if the parser is ever reused for a wider field.
 */
const MAX_SAFE_WINDOW = Number.MAX_SAFE_INTEGER;

/**
 * Error thrown when a window-adjust message cannot be parsed.
 */
export class WindowAdjustError extends Error {
  constructor(message) {
    super(message);
    this.name = 'WindowAdjustError';
  }
}

/**
 * Parse an SSH_MSG_CHANNEL_WINDOW_ADJUST payload.
 *
 * The payload must begin with the message type byte (93). Some transports
 * hand the payload without the type byte, so `parseWindowAdjust` accepts an
 * option to say so explicitly rather than guessing: guessing would make a
 * truncated message look valid.
 *
 * @param {Uint8Array} payload raw message bytes
 * @param {{hasTypeByte?: boolean}} [options]
 * @returns {{recipientChannel: number, windowSize: number}}
 */
export function parseWindowAdjust(payload, options = {}) {
  const hasTypeByte = options.hasTypeByte !== false;

  if (!(payload instanceof Uint8Array)) {
    throw new WindowAdjustError('payload must be a Uint8Array');
  }

  const offset = hasTypeByte ? 1 : 0;
  const required = offset + 8;

  if (payload.length < required) {
    throw new WindowAdjustError(
      `payload too short: expected at least ${required} bytes, got ${payload.length}`
    );
  }

  if (hasTypeByte && payload[0] !== WINDOW_ADJUST_TYPE) {
    throw new WindowAdjustError(
      `unexpected message type: expected ${WINDOW_ADJUST_TYPE}, got ${payload[0]}`
    );
  }

  const recipientChannel = readUint32(payload, offset);
  const windowSize = readUint32(payload, offset + 4);

  if (windowSize > MAX_SAFE_WINDOW) {
    throw new WindowAdjustError('window size exceeds safe integer range');
  }

  return { recipientChannel, windowSize };
}

/**
 * Read a big-endian uint32 from a byte array.
 *
 * We do the shifts manually instead of using DataView so the function works
 * on any Uint8Array without needing to know its byteOffset or buffer layout.
 *
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {number}
 */
function readUint32(bytes, offset) {
  return (
    (bytes[offset] * 0x1000000) +
    ((bytes[offset + 1] << 16) | 0) +
    ((bytes[offset + 2] << 8) | 0) +
    bytes[offset + 3]
  );
}

/**
 * Encode a window-adjust payload.
 *
 * The encoder mirrors the parser: by default it writes the type byte, and
 * callers can omit it for transports that strip it. Both fields are range
 * checked so a bad value fails at the boundary rather than producing bytes
 * that the parser would later reject.
 *
 * @param {number} recipientChannel
 * @param {number} windowSize
 * @param {{includeTypeByte?: boolean}} [options]
 * @returns {Uint8Array}
 */
export function encodeWindowAdjust(recipientChannel, windowSize, options = {}) {
  const includeTypeByte = options.includeTypeByte !== false;

  if (!Number.isInteger(recipientChannel) || recipientChannel < 0 || recipientChannel > 0xffffffff) {
    throw new WindowAdjustError('recipientChannel must be a uint32');
  }
  if (!Number.isInteger(windowSize) || windowSize < 0 || windowSize > 0xffffffff) {
    throw new WindowAdjustError('windowSize must be a uint32');
  }

  const out = new Uint8Array(includeTypeByte ? 9 : 8);
  let offset = 0;
  if (includeTypeByte) {
    out[offset++] = WINDOW_ADJUST_TYPE;
  }
  writeUint32(out, offset, recipientChannel);
  writeUint32(out, offset + 4, windowSize);
  return out;
}

/**
 * Write a big-endian uint32 into a byte array.
 *
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @param {number} value
 */
function writeUint32(bytes, offset, value) {
  bytes[offset] = (value >>> 24) & 0xff;
  bytes[offset + 1] = (value >>> 16) & 0xff;
  bytes[offset + 2] = (value >>> 8) & 0xff;
  bytes[offset + 3] = value & 0xff;
}

/**
 * Tracks the advertised remote window for one SSH channel.
 *
 * SSH flow control is credit based: each side advertises a window and the
 * peer sends window-adjust messages as it consumes data. This class keeps
 * the local accounting so a caller can decide when to stop reading. Window
 * sizes are added, not set, and the class refuses to overflow past
 * MAX_SAFE_WINDOW so a broken peer cannot wrap the counter.
 */
export class WindowTracker {
  /**
   * @param {number} initialWindow starting window in bytes
   */
  constructor(initialWindow) {
    if (!Number.isInteger(initialWindow) || initialWindow < 0 || initialWindow > MAX_SAFE_WINDOW) {
      throw new WindowAdjustError('initialWindow must be a non-negative safe integer');
    }
    this.window = initialWindow;
  }

  /**
   * Apply a parsed window-adjust message.
   *
   * @param {{recipientChannel: number, windowSize: number}} adjustment
   * @returns {number} the new window size
   */
  apply(adjustment) {
    if (adjustment === null || typeof adjustment !== 'object') {
      throw new WindowAdjustError('adjustment must be an object');
    }
    const { windowSize } = adjustment;
    if (!Number.isInteger(windowSize) || windowSize < 0) {
      throw new WindowAdjustError('windowSize must be a non-negative integer');
    }
    const next = this.window + windowSize;
    if (next > MAX_SAFE_WINDOW) {
      throw new WindowAdjustError('window would overflow safe integer range');
    }
    this.window = next;
    return this.window;
  }

  /**
   * Consume bytes from the window.
   *
   * @param {number} bytes
   * @returns {number} the remaining window
   */
  consume(bytes) {
    if (!Number.isInteger(bytes) || bytes < 0) {
      throw new WindowAdjustError('bytes must be a non-negative integer');
    }
    if (bytes > this.window) {
      throw new WindowAdjustError('cannot consume more than the available window');
    }
    this.window -= bytes;
    return this.window;
  }
}
