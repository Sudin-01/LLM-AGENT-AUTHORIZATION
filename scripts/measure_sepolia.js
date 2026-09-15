// scripts/measure_sepolia.js
/**
 * Sepolia testnet measurement for the BlockGuard paper.
 *
 * Measures, against the deployed AgentPermissionRegistry:
 *   1. 50 checkPermission view calls  -> read (enforcement-path) latency
 *   2. 50 logDecision transactions    -> write (audit-path) latency + gas,
 *      each waiting for 1 confirmation before sending the next.
 *
 * Usage:
 *   SEPOLIA_URL=<rpc> PRIVATE_KEY=<key> npx hardhat run scripts/measure_sepolia.js --network sepolia
 *
 * Output: experiments/results_sepolia/sepolia_reads.csv,
 *         experiments/results_sepolia/sepolia_writes.csv,
 *         experiments/results_sepolia/sepolia_summary.txt
 */

const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

const N_READS = 50;
const N_WRITES = 50;

const AGENTS = ["agent_a", "agent_b", "agent_c"];
const ACTIONS = ["search_web", "read_file", "transfer_money", "execute_command", "delete_database"];

function percentile(sorted, p) {
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

function stats(values) {
  const s = [...values].sort((a, b) => a - b);
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  const std = Math.sqrt(s.reduce((a, b) => a + (b - mean) ** 2, 0) / s.length);
  return {
    n: s.length,
    mean,
    std,
    min: s[0],
    median: percentile(s, 50),
    p95: percentile(s, 95),
    max: s[s.length - 1],
  };
}

async function main() {
  const configPath = path.join(__dirname, "../backend/config.json");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  // Prefer the environment so the address need not be committed while the
  // paper is under anonymous review; fall back to config.json otherwise.
  const contractAddress = process.env.SEPOLIA_CONTRACT || config.sepolia.contractAddress;
  if (!contractAddress) {
    throw new Error("set SEPOLIA_CONTRACT (or restore backend/config.json sepolia.contractAddress)");
  }

  const [signer] = await hre.ethers.getSigners();
  const contract = await hre.ethers.getContractAt("AgentPermissionRegistry", contractAddress, signer);
  const toBytes32 = (s) => hre.ethers.encodeBytes32String(s.substring(0, 31));

  // SEPOLIA_SESSION lets the same deployed contract be measured more than once
  // (e.g. at different times of day) so network-condition variance is visible.
  const session = process.env.SEPOLIA_SESSION || "";
  const outDir = path.join(__dirname,
      "../experiments/results_sepolia" + (session ? `_${session}` : ""));
  fs.mkdirSync(outDir, { recursive: true });

  console.log("Network :", hre.network.name);
  console.log("Contract:", contractAddress);
  console.log("Signer  :", signer.address);
  console.log(
    "Balance :",
    hre.ethers.formatEther(await hre.ethers.provider.getBalance(signer.address)),
    "ETH\n"
  );

  // ── 1. Read latency: checkPermission view calls ────────────────────────────
  console.log(`── ${N_READS} checkPermission view calls ──`);
  const reads = [];
  for (let i = 0; i < N_READS; i++) {
    const agent = AGENTS[i % AGENTS.length];
    const action = ACTIONS[i % ACTIONS.length];
    const t0 = Date.now();
    const permitted = await contract.checkPermission(toBytes32(agent), toBytes32(action));
    const latency = Date.now() - t0;
    reads.push({ i: i + 1, agent, action, permitted, latency_ms: latency });
    process.stdout.write(`\r  read ${i + 1}/${N_READS}  ${latency} ms   `);
  }
  console.log("\n");

  // ── 2. Write latency + gas: logDecision transactions ───────────────────────
  console.log(`── ${N_WRITES} logDecision transactions (each waits for 1 confirmation) ──`);
  const writes = [];
  for (let i = 0; i < N_WRITES; i++) {
    const agent = AGENTS[i % AGENTS.length];
    const action = ACTIONS[i % ACTIONS.length];
    const permitted = await contract.checkPermission(toBytes32(agent), toBytes32(action));
    const requestHash = hre.ethers.keccak256(
      hre.ethers.toUtf8Bytes(`${agent}|${action}|${Date.now()}|trial_${i}`)
    );

    const t0 = Date.now();
    const tx = await contract.logDecision(toBytes32(agent), toBytes32(action), permitted, requestHash);
    const tSent = Date.now();
    const receipt = await tx.wait(1);
    const tConfirmed = Date.now();

    const feeWei = receipt.gasUsed * receipt.gasPrice;
    writes.push({
      i: i + 1,
      agent,
      action,
      permitted,
      tx_hash: receipt.hash,
      block: receipt.blockNumber,
      gas_used: Number(receipt.gasUsed),
      gas_price_gwei: Number(receipt.gasPrice) / 1e9,
      fee_eth: Number(hre.ethers.formatEther(feeWei)),
      submit_ms: tSent - t0,
      confirm_ms: tConfirmed - tSent,
      total_ms: tConfirmed - t0,
    });
    console.log(
      `  tx ${i + 1}/${N_WRITES}  block=${receipt.blockNumber}  gas=${receipt.gasUsed}  ` +
        `total=${((tConfirmed - t0) / 1000).toFixed(1)}s  ${receipt.hash.slice(0, 18)}…`
    );
  }

  // ── 3. Write CSVs ───────────────────────────────────────────────────────────
  const readCsv =
    "trial,agent,action,permitted,latency_ms\n" +
    reads.map((r) => `${r.i},${r.agent},${r.action},${r.permitted},${r.latency_ms}`).join("\n") +
    "\n";
  fs.writeFileSync(path.join(outDir, "sepolia_reads.csv"), readCsv);

  const writeCsv =
    "trial,agent,action,permitted,tx_hash,block,gas_used,gas_price_gwei,fee_eth,submit_ms,confirm_ms,total_ms\n" +
    writes
      .map(
        (w) =>
          `${w.i},${w.agent},${w.action},${w.permitted},${w.tx_hash},${w.block},${w.gas_used},` +
          `${w.gas_price_gwei.toFixed(3)},${w.fee_eth.toFixed(8)},${w.submit_ms},${w.confirm_ms},${w.total_ms}`
      )
      .join("\n") +
    "\n";
  fs.writeFileSync(path.join(outDir, "sepolia_writes.csv"), writeCsv);

  // ── 4. Summary ──────────────────────────────────────────────────────────────
  const rs = stats(reads.map((r) => r.latency_ms));
  const ws = stats(writes.map((w) => w.total_ms));
  const gs = stats(writes.map((w) => w.gas_used));
  const totalFee = writes.reduce((a, w) => a + w.fee_eth, 0);

  const summary = [
    "SEPOLIA TESTNET MEASUREMENT — AgentPermissionRegistry",
    `Contract: ${contractAddress}`,
    `Date: ${new Date().toISOString()}`,
    `RPC: ${process.env.SEPOLIA_URL}`,
    `Session: ${session || "1"}`,
    "",
    `READ LATENCY — checkPermission view call (n=${rs.n})`,
    `  mean=${rs.mean.toFixed(1)}ms  median=${rs.median}ms  p95=${rs.p95}ms  min=${rs.min}ms  max=${rs.max}ms  std=${rs.std.toFixed(1)}ms`,
    "",
    `WRITE LATENCY — logDecision, submit → 1 confirmation (n=${ws.n})`,
    `  mean=${(ws.mean / 1000).toFixed(2)}s  median=${(ws.median / 1000).toFixed(2)}s  p95=${(ws.p95 / 1000).toFixed(2)}s  min=${(ws.min / 1000).toFixed(2)}s  max=${(ws.max / 1000).toFixed(2)}s  std=${(ws.std / 1000).toFixed(2)}s`,
    "",
    `GAS — logDecision (n=${gs.n})`,
    `  mean=${Math.round(gs.mean)}  median=${gs.median}  min=${gs.min}  max=${gs.max}  std=${Math.round(gs.std)}`,
    `  total fee for ${N_WRITES} tx: ${totalFee.toFixed(6)} ETH`,
    "",
    `Blocks spanned: ${writes[0].block} – ${writes[writes.length - 1].block}`,
    `All tx hashes verifiable at https://sepolia.etherscan.io/address/${contractAddress}`,
  ].join("\n");

  fs.writeFileSync(path.join(outDir, "sepolia_summary.txt"), summary + "\n");
  console.log("\n" + summary);
  console.log(`\n✓ Results written to ${outDir}`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
