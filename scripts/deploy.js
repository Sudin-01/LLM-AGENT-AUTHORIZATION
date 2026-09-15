// scripts/deploy.js
/**
 * Deployment script for AgentPermissionRegistry.
 *
 * Usage:
 *   npx hardhat run scripts/deploy.js --network ganache
 *   npx hardhat run scripts/deploy.js --network hardhat
 *   npx hardhat run scripts/deploy.js --network sepolia
 *
 * After deployment, copy the contract address into backend/config.json
 */

const hre = require("hardhat");
const fs  = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);
  console.log(
    "Account balance:",
    hre.ethers.formatEther(await hre.ethers.provider.getBalance(deployer.address)),
    "ETH"
  );

  // ── Deploy ─────────────────────────────────────────────────────────────────
  const Factory = await hre.ethers.getContractFactory("AgentPermissionRegistry");
  const contract = await Factory.deploy();
  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  console.log("\n✓ AgentPermissionRegistry deployed to:", contractAddress);

  // ── Seed initial permissions for agent_a ───────────────────────────────────
  const toBytes32 = (s) =>
    hre.ethers.encodeBytes32String(s.substring(0, 31));  // max 31 bytes + null

  const agents   = ["agent_a", "agent_a", "agent_a", "agent_a", "agent_a",
                    "agent_b", "agent_b", "agent_b", "agent_b", "agent_b",
                    "agent_c", "agent_c", "agent_c", "agent_c", "agent_c"];
  const actions  = ["search_web", "read_file", "transfer_money", "execute_command", "delete_database",
                    "search_web", "read_file", "transfer_money", "execute_command", "delete_database",
                    "search_web", "read_file", "transfer_money", "execute_command", "delete_database"];
  const perms    = [true, true, false, false, false,
                    true, true, true,  false, false,
                    true, true, false, false, false];

  console.log("\nSetting initial permissions...");
  const tx = await contract.batchSetPermissions(
    agents.map(toBytes32),
    actions.map(toBytes32),
    perms
  );
  await tx.wait();
  console.log("✓ Initial permissions set (tx:", tx.hash, ")");

  // ── Save deployment info ───────────────────────────────────────────────────
  const network = hre.network.name;
  const deployInfo = {
    network,
    contractAddress,
    deployerAddress: deployer.address,
    deployedAt: new Date().toISOString(),
    txHash: contract.deploymentTransaction()?.hash || "",
    abi: "See artifacts/contracts/AgentPermissionRegistry.sol/AgentPermissionRegistry.json",
  };

  const configPath = path.join(__dirname, "../backend/config.json");
  let existing = {};
  if (fs.existsSync(configPath)) {
    existing = JSON.parse(fs.readFileSync(configPath, "utf8"));
  }
  existing[network] = deployInfo;
  fs.writeFileSync(configPath, JSON.stringify(existing, null, 2));
  console.log("\n✓ Deployment info saved to backend/config.json");
  console.log("\n── Deployment Summary ────────────────────────────────────────");
  console.log(JSON.stringify(deployInfo, null, 2));
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
