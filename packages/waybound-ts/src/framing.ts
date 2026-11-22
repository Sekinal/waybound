/** Line-delimited JSON framing for the daemon wire protocol. */

const NEWLINE = 0x0a;

/** Default cap on a single reply line; a larger line means a broken or hostile peer. */
export const DEFAULT_MAX_LINE_BYTES = 256 * 1024 * 1024;

/**
 * Splits a byte stream into `\n`-terminated lines.
 *
 * Bytes are buffered until a newline arrives and each complete line is decoded as UTF-8 in
 * one piece. A `\n` byte never occurs inside a multi-byte UTF-8 sequence, so characters split
 * across chunks are reassembled correctly, and several lines coalesced in one chunk are all
 * returned.
 */
export class LineDecoder {
  readonly #maxLineBytes: number;
  readonly #decoder = new TextDecoder("utf-8", { fatal: true });
  #chunks: Buffer[] = [];
  #pendingBytes = 0;

  constructor(maxLineBytes: number = DEFAULT_MAX_LINE_BYTES) {
    this.#maxLineBytes = maxLineBytes;
  }

  /** Number of buffered bytes that do not yet form a complete line. */
  get pendingBytes(): number {
    return this.#pendingBytes;
  }

  /**
   * Feed a chunk and return every complete line it finishes (without the trailing `\n` or a
   * trailing `\r`). Throws `RangeError` if a line exceeds the cap and `TypeError` if a line is
   * not valid UTF-8.
   */
  push(chunk: Buffer): string[] {
    const lines: string[] = [];
    let start = 0;
    for (;;) {
      const idx = chunk.indexOf(NEWLINE, start);
      if (idx === -1) {
        break;
      }
      const piece = chunk.subarray(start, idx);
      this.#checkSize(piece.length);
      const line = this.#chunks.length === 0 ? piece : Buffer.concat([...this.#chunks, piece]);
      this.#chunks = [];
      this.#pendingBytes = 0;
      lines.push(this.#decode(line));
      start = idx + 1;
    }
    if (start < chunk.length) {
      const rest = chunk.subarray(start);
      this.#checkSize(rest.length);
      this.#chunks.push(rest);
      this.#pendingBytes += rest.length;
    }
    return lines;
  }

  #checkSize(extra: number): void {
    if (this.#pendingBytes + extra > this.#maxLineBytes) {
      throw new RangeError(`reply line exceeded ${this.#maxLineBytes}-byte limit`);
    }
  }

  #decode(line: Buffer): string {
    const text = this.#decoder.decode(line);
    return text.endsWith("\r") ? text.slice(0, -1) : text;
  }
}

/** Encode one request object as a single newline-terminated JSON line. */
export function encodeLine(payload: Readonly<Record<string, unknown>>): string {
  return `${JSON.stringify(payload)}\n`;
}
