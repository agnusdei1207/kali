# DreamHack CTF — Hidden Text (Challenge 3166)

> **Working writeup:** The hidden text has been identified as zero-width Unicode and decoded into three Korean lines. The final clue target and flag still need to be confirmed, so this runbook records the verified steps and leaves the result section open.

## Challenge details

- **Platform:** DreamHack Wargame
- **Challenge:** [3166](https://dreamhack.io/wargame/challenges/3166)
- **Category:** Miscellaneous / Cryptography
- **Difficulty:** Bronze 1
- **Goal:** Recover the clue hidden in the challenge description and submit the flag in the format `DH{...}`.

## Reasoning summary

1. The downloaded archive contains only a README that points back to the challenge page, so inspect the page metadata and description.
2. Both the title and description contain zero-width Unicode characters. Map those characters to bits and decode the resulting text.
3. The description has three `<br>`-separated payload lines. Decode each line independently to preserve its byte boundary.
4. The message says the flag is not in the archive and points to the date of the first DreamHack CTF. Check the official CTF record, then test the date in the expected flag format.

## 1. Check the downloaded file

The downloaded `item.zip` contains a short `README.md`:

```text
flag 형식은 DH{...}
문제 페이지에 힌트가?
```

The README says the flag uses the `DH{...}` format and asks whether there is a hint on the challenge page. The archive does not contain the hidden payload, so inspect the page itself.

## 2. Inspect the challenge title and description

The title is also hidden. The challenge metadata API returns a title made only of U+200B and U+200C. Decode it with the same bit-to-byte process; its Base64 payload is `ZmxhZ+uKlA==`, which decodes to `flag는` (“as for the flag…”). Read together with the description, this completes the sentence: the flag is not here, but a hint exists.

From the signed-in challenge page, the title can be checked in the browser console:

```js
(async () => {
  const challenge = await fetch("/api/v1/wargame/challenges/3166/").then(r => r.json());
  const bits = [...challenge.title]
    .filter(c => c === "\u200b" || c === "\u200c")
    .map(c => c === "\u200c" ? "1" : "0").join("");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  const base64 = String.fromCharCode(...bytes);
  const raw = atob(base64);
  console.log(new TextDecoder().decode(Uint8Array.from(raw, c => c.charCodeAt(0))));
})();
```

### Inspect the raw description

The visible description may look like ordinary translated text, but its HTML contains three lines made from invisible characters. In DevTools, inspect the `<p>` under `#challenge-description` and look for entities such as:

- `&ZeroWidthSpace;` — U+200B, ZERO WIDTH SPACE
- `&zwnj;` — U+200C, ZERO WIDTH NON-JOINER

These characters take up no visible width. They are still distinct Unicode code points, so they can represent data. Here, treat U+200B as bit `0` and U+200C as bit `1`.

The `<br>` tags divide the payload into three lines. Keep those lines separate while extracting; joining them first can shift byte boundaries and produce corrupted output.

## 3. Extract each line as bits and bytes

Open the browser DevTools Console on the challenge page. If Chrome blocks pasting, type `allow pasting` into the console and press Enter. This is a browser safeguard, not an error in the decoder.

Run this script. It reads only the challenge description, maps the two invisible characters to bits, groups each line into 8-bit bytes, and prints the resulting ASCII text. It also tries to decode any Base64-looking text on each line.

```js
(() => {
  const p = document.querySelector("#challenge-description p");
  if (!p) {
    console.log("Could not find the challenge description paragraph.");
    return;
  }

  // A <br> separates the payload into text nodes, one per line.
  const lines = [...p.childNodes].filter(n => n.nodeType === Node.TEXT_NODE);

  for (const [index, node] of lines.entries()) {
    const chars = [...node.textContent].filter(
      c => c === "\u200b" || c === "\u200c"
    );
    const bits = chars.map(c => c === "\u200c" ? "1" : "0").join("");
    const bytes = [];

    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }

    const text = String.fromCharCode(...bytes);
    console.log(`--- line ${index + 1} ---`);
    console.log({ bitCount: bits.length, leftoverBits: bits.length % 8, text });

    // Decode Base64 blocks independently. Padding (=) marks a block boundary.
    const blocks = text.match(/[A-Za-z0-9+/]+={0,2}/g) || [];
    for (const [blockIndex, block] of blocks.entries()) {
      try {
        const padded = block.padEnd(Math.ceil(block.length / 4) * 4, "=");
        const binary = atob(padded);
        const data = Uint8Array.from(binary, c => c.charCodeAt(0));
        console.log(`Base64 block ${blockIndex + 1}:`, new TextDecoder().decode(data));
      } catch (error) {
        console.log(`Base64 block ${blockIndex + 1} could not be decoded:`, String(error));
      }
    }
  }
})();
```

### What each stage means

1. **Unicode characters to bits:** U+200B and U+200C are two visually blank but different characters. Assigning them `0` and `1` turns the hidden sequence into a binary string.
2. **Bits to bytes:** Eight bits make one byte. Parsing each group in base 2 produces a number from 0 to 255.
3. **Bytes to text:** The payload bytes currently appear to be ASCII characters that form Base64. This is a common encoding layer: Base64 represents bytes as printable text; it is not encryption.
4. **Base64 to plaintext:** Decode each complete Base64 block, then interpret its bytes as UTF-8. If the result contains replacement characters, first check that the correct line and block boundaries were used and that no characters were lost while copying.

## 4. Read the current extraction carefully

Combining all three lines in one pass produced 824 bits with no leftover bits, but it joined separate Base64 blocks and made the later output look corrupted. Processing each `<br>`-separated line independently produced these verified results:

```text
7Jes6riw7JeQIOyXhuydjOyalA==7ZWY7KeA66eMIO2ejO2KuO...
```

The three independently decoded lines are:

```text
여기에 없음요
하지만 힌트는 있음
최초의 드림핵 ctf ㄴㅉ
```

The title `flag는` plus line 1 `여기에 없음요` means “The flag is not here.” Line 2 says “But there is a hint.” In line 3, `ㄴㅉ` is the Korean initial-consonant shorthand for `날짜` (“date”), so the full clue is “the date of the first DreamHack CTF.” The per-line bit counts are 224, 280, and 320, with no leftover bits on any line.

## 5. DevTools troubleshooting

- **Chrome says “Don’t paste code…”:** type `allow pasting` manually and press Enter, then paste the reviewed script.
- **`SyntaxError: Invalid or unexpected token`:** cancel the current console input with Esc, then paste the complete script as one unit. Avoid copying code from a syntax-highlighted screenshot; it can omit or alter punctuation.
- **The script says it cannot find the paragraph:** confirm the challenge page is open and that its description is present. The selector used is `#challenge-description p`.
- **The decoded text looks corrupted:** check each line’s `bitCount` and `leftoverBits`. A nonzero remainder or a block that crosses a line boundary can shift every following byte. Copy the console’s expanded `text` value, not a preview containing an ellipsis.
- **Base64 decode throws a padding error:** make sure the block is complete. Do not join text across a `=` padding boundary; decode the blocks separately.

## 6. Key takeaways

- Text can carry data through invisible Unicode code points even when it appears blank in the rendered page.
- Inspecting the DOM or page metadata can reveal content that translation and normal rendering conceal.
- Preserve logical boundaries such as `<br>` elements when converting bits into bytes.
- Base64 only changes representation; the decoded bytes still need to be interpreted using the correct character encoding.
- Treat an externally derived answer as a candidate until the challenge accepts it.

## 7. Finish the solve

The clue asks for the date of the first DreamHack CTF. Search results also refer to the inaugural event as **Dreamhack CTF Pre-Season Round #1**. DreamHack's official event page lists **Dreamhack CTF Season 1 Round #1** from **2020.09.29 10:00:00 to 18:00:00** ([official event page](https://dreamhack.io/ctf/1)).

`DH{20200929}` was submitted and rejected. The clue still points to the event date, but the expected flag representation has not been confirmed. Next test the date as displayed on the official event page, `DH{2020.09.29}`, and then include the start time only if needed.

### Decoded lines

```text
Line 1 (224 bits): 여기에 없음요
Line 2 (280 bits): 하지만 힌트는 있음
Line 3 (320 bits): 최초의 드림핵 ctf ㄴㅉ
```

### Solution and flag

The clue resolves to the first DreamHack CTF, Season 1 Round #1 (also called Pre-Season Round #1 in contemporaneous writeups), held on 2020-09-29. `DH{20200929}` was rejected. **Next candidate:** `DH{2020.09.29}`. The accepted flag still needs to be confirmed on the challenge page.
