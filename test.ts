import readline from "node:readline";
import { Validator } from "./dist/index.esm";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on("line", async (line) => {
  const event = JSON.parse(line);
  const validator = new Validator({ allowExpired: true, printLogs: true });

  try {
    if (event.kind === 63793)
    await validator.validateInstance(event);
  else if (event.kind === 13196)
    await validator.validateEnclavedEvent(event);
  else return;

  console.log("valid", event.kind, event.id);

  } catch (e) {
    console.log("invalid", event.kind, event.id)
  }
});
