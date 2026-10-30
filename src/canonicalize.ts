// OLPC and JCS slightly differs, especially on character encodings and integers.
//   - OLPC (http://wiki.laptop.org/go/Canonical_JSON): TUF metadata and keyids.
//   - JCS / RFC 8785: Rekor signed entry timestamps and WEBCAT

const COMMA = ",";
const COLON = ":";
const LEFT_SQUARE_BRACKET = "[";
const RIGHT_SQUARE_BRACKET = "]";
const LEFT_CURLY_BRACKET = "{";
const RIGHT_CURLY_BRACKET = "}";

// OLPC escapes only backslash and double quote. Control characters and
// non-ASCII are emitted raw.
function canonicalizeStringOLPC(string: string): string {
  const escapedString = string.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return '"' + escapedString + '"';
}

// Compares two strings by Unicode code point, which is also UTF-8 byte order
// and what the olpc-cjson crate and python-tuf sort keys by.
// Array.prototype.sort() compares UTF-16 code units instead, which puts
// U+10000 (surrogates D800 DC00) before U+FFFF.
function compareCodePoints(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const codePointA = a.codePointAt(i) as number;
    const codePointB = b.codePointAt(j) as number;
    if (codePointA !== codePointB) {
      return codePointA - codePointB;
    }
    i += codePointA > 0xffff ? 2 : 1;
    j += codePointB > 0xffff ? 2 : 1;
  }
  // One string is a prefix of the other (or they are equal): shorter sorts first.
  return a.length - i - (b.length - j);
}

// Recursively encodes the supplied value as OLPC canonical JSON: keys sorted by
// code point, only double quotes and backslashes escaped, integers only and only
// in the JS safe range so nothing is silently rounded. Throws on anything else.
export function canonicalizeOLPC(object: unknown): string {
  const buffer: string[] = [];
  if (typeof object === "string") {
    buffer.push(canonicalizeStringOLPC(object));
  } else if (typeof object === "boolean") {
    buffer.push(JSON.stringify(object));
  } else if (Number.isSafeInteger(object)) {
    buffer.push(JSON.stringify(object));
  } else if (object === null) {
    buffer.push(JSON.stringify(object));
  } else if (Array.isArray(object)) {
    buffer.push(LEFT_SQUARE_BRACKET);
    let first = true;
    for (const element of object) {
      if (!first) {
        buffer.push(COMMA);
      }
      first = false;
      buffer.push(canonicalizeOLPC(element));
    }
    buffer.push(RIGHT_SQUARE_BRACKET);
  } else if (typeof object === "object") {
    const record = object as Record<string, unknown>;
    buffer.push(LEFT_CURLY_BRACKET);
    let first = true;
    for (const property of Object.keys(record).sort(compareCodePoints)) {
      if (!first) {
        buffer.push(COMMA);
      }
      first = false;
      buffer.push(canonicalizeStringOLPC(property));
      buffer.push(COLON);
      buffer.push(canonicalizeOLPC(record[property]));
    }
    buffer.push(RIGHT_CURLY_BRACKET);
  } else {
    throw new TypeError("cannot encode " + String(object));
  }

  return buffer.join("");
}

// Recursively encodes the supplied value per RFC 8785 (JCS): keys sorted by
// UTF-16 code units, strings and numbers serialized exactly as JSON.stringify
// does. Throws on NaN, Infinity, undefined and anything else JSON.
export function canonicalizeJCS(object: unknown): string {
  const buffer: string[] = [];
  if (typeof object === "string") {
    buffer.push(JSON.stringify(object));
  } else if (typeof object === "boolean") {
    buffer.push(JSON.stringify(object));
  } else if (typeof object === "number" && Number.isFinite(object)) {
    buffer.push(JSON.stringify(object));
  } else if (object === null) {
    buffer.push(JSON.stringify(object));
  } else if (Array.isArray(object)) {
    buffer.push(LEFT_SQUARE_BRACKET);
    let first = true;
    for (const element of object) {
      if (!first) {
        buffer.push(COMMA);
      }
      first = false;
      buffer.push(canonicalizeJCS(element));
    }
    buffer.push(RIGHT_SQUARE_BRACKET);
  } else if (typeof object === "object") {
    const record = object as Record<string, unknown>;
    buffer.push(LEFT_CURLY_BRACKET);
    let first = true;
    for (const property of Object.keys(record).sort()) {
      if (!first) {
        buffer.push(COMMA);
      }
      first = false;
      buffer.push(JSON.stringify(property));
      buffer.push(COLON);
      buffer.push(canonicalizeJCS(record[property]));
    }
    buffer.push(RIGHT_CURLY_BRACKET);
  } else {
    throw new TypeError("cannot encode " + String(object));
  }

  return buffer.join("");
}
