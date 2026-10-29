// End-to-end test of the web client's library (ui/client.js) against a real server, with the
// insecure software key. Run a local server with open registration, then:
//
//   node apps/web/test/e2e.mjs http://127.0.0.1:8080 [softkey.json]
//
// The software key's state file has the same format as the Rust one (crates/fido/src/soft.rs),
// so the Rust CLI or desktop app (`--soft`) can open what this test leaves behind.

import fs from "node:fs";
import * as client from "../ui/client.js";
import { softAuthenticator } from "../ui/authn.js";

const [server = "http://127.0.0.1:8080", softFile = "softkey-web-e2e.json"] = process.argv.slice(2);
const store = {
  load: () => { try { return JSON.parse(fs.readFileSync(softFile, "utf8")); } catch { return {}; } },
  save: (s) => fs.writeFileSync(softFile, JSON.stringify(s, null, 2)),
};
const key1 = softAuthenticator(store);
// A second "physical key": its own state, so its credentials are not key1's.
const key2State = {};
const key2 = softAuthenticator({ load: () => key2State, save: (s) => Object.assign(key2State, s) });

let failures = 0;
const check = (ok, what) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) failures++; };
const rejects = async (p, re, what) => {
  try { await p; check(false, `${what} (did not fail)`); } catch (e) { check(re.test(e.message), `${what}: ${e.message}`); }
};
const random = (n) => { const b = new Uint8Array(n); for (let i = 0; i < n; i += 65536) crypto.getRandomValues(b.subarray(i, i + 65536)); return b; };
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

const user = `e2e-${Date.now().toString(36)}`;
const PIN = "12345678", PIN2 = "87654321";
console.log(`server ${server}, username ${user}, soft key ${softFile}`);

const acct = await client.createVaultNamed(server, user, null, key1, "Key one");
check(acct.members.length === 1, "account created with one key");
const accountCode = await acct.newAccountRecoveryCodeNamed("Account code");
await rejects(acct.newAccountRecoveryCodeNamed("account CODE "), /already named/, "duplicate labels are refused");
check(acct.suggestLabel("Account code", []) === "Account code 2", "label suggestion");

// A drive: create, upload in a batch, reopen.
const { client: c1, key } = await client.connect(server, user, key1, 1, PIN);
const drive = await c1.create(key);
const data = random(600_000);
const staged = drive.stage();
drive.mkdirPStaged(staged, "/a/b");
const name = await drive.uploadStaged(staged, new File([data], "data.bin"), "/a");
await drive.uploadStaged(staged, new File([], "empty"), "/a/b");
await drive.commitStaged(staged);
check(name === "data.bin" && drive.list("/a").length === 2, "batched upload");
const again = await drive.uploadStaged(drive.stage(), new File([data], "data.bin"), "/a", { onConflict: "keep_both" });
check(again === "data (1).bin", "keep both renames");
const reopened = await c1.open(key);
check(same(await reopened.readFile("/a/data.bin", 1e9), data), "content survives reopen");
check((await c1.open(await c1.slotKey(key1, 1, PIN2))) === null, "wrong PIN opens nothing");
check((await c1.open(await c1.slotKey(key1, 2, PIN))) === null, "unused slot opens nothing");
await rejects(c1.slotKey(key1, 1, "1234567"), /too short/, "short PIN refused");

// Recovery code for this drive.
const vaultCode = await reopened.newRecoveryCodeNamed("Vault code");
const rec = await client.connectWithRecovery(server, user, vaultCode);
check(rec.key.slot === 1 && same(await rec.drive.readFile("/a/data.bin", 1e9), data), "vault recovery code opens the drive");
await rejects(client.connectAccountWithRecovery(server, user, vaultCode), /not an account recovery code/, "vault code is not an account code");
await client.connectAccountWithRecovery(server, user, accountCode);
check(true, "account recovery code signs in");

// A backup key: account sign-in, then granted this drive.
await reopened.client.addAccountKeyNamed(key2, "Key two");
const k2id = reopened.client.members.find((m) => m.label === "Key two").id;
await reopened.grantAccountKey(key2, PIN, k2id);
const { client: c2, key: kk2 } = await client.connect(server, user, key2, 1, PIN);
check((await c2.open(kk2)) !== null, "granted key opens the drive");
// Changing the PIN revokes the other key; the new PIN works for key one.
const fresh = await c1.open(key);
const revoked = await fresh.changePin(key1, PIN2);
check(revoked === 1, "PIN change revokes the other key");
check((await c2.open(await c2.slotKey(key2, 1, PIN))) === null, "revoked key no longer opens the drive");
const { client: c3, key: k3 } = await client.connect(server, user, key1, 1, PIN2);
const d3 = await c3.open(k3);
check(d3 !== null && (await c3.open(await c3.slotKey(key1, 1, PIN))) === null, "new PIN opens, old does not");
// Rename and remove members.
await c3.renameMember(k2id, "Spare key");
check(c3.members.some((m) => m.label === "Spare key"), "rename member");
await c3.removeMember(k2id);
await rejects(client.connectAccount(server, user, key2), /not registered/, "removed key cannot sign in");
await d3.revokeRecoveryCode(d3.recoveryIds()[0]);
await rejects(client.connectWithRecovery(server, user, vaultCode), /./, "revoked recovery code fails");

// Edits, then a wiped drive refuses to work.
await d3.rename("/a/data.bin", "/moved.bin");
await d3.remove("/a");
check(d3.search("MOVED").length === 1 && d3.list("/").length === 1, "rename, remove, search");
d3.wipe();
await rejects(d3.readFile("/moved.bin", 1e9), /locked/, "wiped drive stops decrypting");
await rejects(client.connect(server, `${user}-nobody`, key1, 1, PIN), /unknown username/, "unknown username");

fs.writeFileSync(`${softFile}.account`, JSON.stringify({ user, pin: PIN2, slot: 1, file: "/moved.bin" }));
console.log(failures ? `${failures} FAILED` : "all passed");
process.exit(failures ? 1 : 0);
