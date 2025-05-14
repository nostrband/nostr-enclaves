# Nostr Enclaves Tests

This directory contains test implementations for both Node.js and browser environments.

## Node.js Tests

To run the Node.js tests, you can feed events from nak to the test code:

```bash
nak req -k 63793 wss://relay.nostr.band  | node node.test.ts
```

## Browser Tests

Open `tests/browser.html` in your browser and paste and event into the textarea.
