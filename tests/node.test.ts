import readline from "node:readline";
import { Validator } from "../dist";

async function runNodeTests() {
  const validator = new Validator({
    allowExpired: false,
    printLogs: true,
    // expectedPcrs: new Map([
    //   [0, hexToBytes("6dc806f3a214e71f4a468979704c90abe1e6597af6360dbd92d9ba1861300be6c48a5e4c95e453046d48fa62b6b296f8")],
    //   [1, hexToBytes("4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493")],
    //   [2, hexToBytes("d4832bd8fd73135d7a8b1f8f26e31a2b55e68b0f430640b15ffaeb250a38d415e9b83e7511e0a58660222579b8976ccd")],
    // ])
    // expectedRelease: {
    //   ref: "https://github.com/nostrband/keycrux",
    //   signerPubkeys: ["3356de61b39647931ce8b2140b2bab837e0810c0ef515bbe92de0248040b8bdd"],
    // }
  });

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

      let validExpectations = false;
      try {
        if (event.kind === 63793) {
          validExpectations = await validator.validateInstance(event);
        } else if (event.kind === 13196) {
          await validator.validateEnclavedEvent(event);
        } else {
          console.log("skipped: unsupported event kind", event.kind);
          return;
        }

        if (validExpectations) console.log("valid", event.kind, event.id);
        else console.log("invalid expectations", event.kind, event.id);
      } catch (e) {
        console.log("invalid", event.kind, event.id, e.message);
      }
    } catch (e) {
      console.log("invalid: failed to parse JSON");
    }
  });
}

runNodeTests();
