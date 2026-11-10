# ssh-connection-window-size-ts

Parses and builds SSH channel window-adjust messages (RFC 4254 section 5.2) so a transport can keep flow-control accounting without pulling in a full SSH stack.

```js
import {
  parseWindowAdjust,
  encodeWindowAdjust,
  WindowTracker,
} from './src/index.js';

// A 9-byte payload: type 93, recipient channel 7, add 4096 bytes.
const payload = encodeWindowAdjust(7, 4096);
const { recipientChannel, windowSize } = parseWindowAdjust(payload);

const tracker = new WindowTracker(0);
tracker.apply({ recipientChannel, windowSize });
tracker.consume(1024);
console.log(tracker.window); // 3072
```

## Why this exists

SSH flow control is credit based, and the window-adjust message is a tiny fixed-layout record: a type byte, a recipient channel, and a big-endian uint32 credit. Implementations that only need this one message should not have to depend on a full SSH library. The trade-off is that this package does exactly one thing: it parses and encodes the payload and keeps a running window counter. It does not do encryption, framing, or channel lifecycle management.

## The awkward edge

Some transports hand you the payload with the message type byte stripped, and some keep it. Rather than sniff the first byte, `parseWindowAdjust` takes an explicit `hasTypeByte` option (default `true`), and `encodeWindowAdjust` takes the matching `includeTypeByte` option. Guessing here would turn a truncated message into a plausible-looking one, so the choice is yours and must be stated at the call site.

The window counter is a JavaScript number, not a `BigInt`. A uint32 always fits safely, and `WindowTracker` throws `WindowAdjustError` rather than silently losing precision if accumulated credits would exceed `Number.MAX_SAFE_INTEGER`.

## API

- `parseWindowAdjust(payload, { hasTypeByte = true })` returns `{ recipientChannel, windowSize }`.
- `encodeWindowAdjust(recipientChannel, windowSize, { includeTypeByte = true })` returns a `Uint8Array`.
- `WindowTracker` holds a window, with `apply(adjustment)` and `consume(bytes)`.
- `WindowAdjustError` is thrown for malformed input and out-of-range values.
