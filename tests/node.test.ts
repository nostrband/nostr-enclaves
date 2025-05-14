import readline from "node:readline";
import { Validator } from "../dist";

async function runNodeTests() {
  const validator = new Validator({ allowExpired: false, printLogs: false });
  
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  rl.on("line", async (line) => {
    try {
      const event = JSON.parse(line);
      
      if (!event || typeof event !== "object") {
        console.log("invalid: not a valid JSON object");
        return;
      }

      try {
        if (event.kind === 63793) {
          await validator.validateInstance(event);
        } else if (event.kind === 13196) {
          await validator.validateEnclavedEvent(event);
        } else {
          console.log("skipped: unsupported event kind", event.kind);
          return;
        }

        console.log("valid", event.kind, event.id);
      } catch (e) {
        console.log("invalid", event.kind, event.id, e.message);
      }
    } catch (e) {
      console.log("invalid: failed to parse JSON");
    }
  });
}

runNodeTests(); 