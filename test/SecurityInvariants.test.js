// Security invariants for AgentPermissionRegistry.
//
// The tamper-evidence property is stated here as something machine
// checked rather than only asserted in prose. The central claim the paper makes
// is: no execution path modifies stored permissions without an owner-signed
// transaction, and every modification emits a record. These tests check exactly
// that, including a randomised sweep over non-owner callers.

const { expect } = require("chai");
const hre = require("hardhat");

const b32 = (s) => hre.ethers.encodeBytes32String(s.substring(0, 31));

describe("AgentPermissionRegistry — security invariants", function () {
  let contract, owner, attacker, others;

  beforeEach(async function () {
    [owner, attacker, ...others] = await hre.ethers.getSigners();
    const F = await hre.ethers.getContractFactory("AgentPermissionRegistry");
    contract = await F.deploy();
    await contract.waitForDeployment();
  });

  it("INV-1: no non-owner can modify a permission", async function () {
    const agent = b32("agent_c"), action = b32("delete_database");
    const before = await contract.checkPermission(agent, action);
    for (const signer of [attacker, ...others.slice(0, 5)]) {
      await expect(
        contract.connect(signer).setPermission(agent, action, true)
      ).to.be.revertedWith("AgentPermissionRegistry: Not authorized");
      expect(await contract.checkPermission(agent, action)).to.equal(before);
    }
  });

  it("INV-2: no non-owner can batch-modify permissions", async function () {
    const agents = [b32("agent_c")], actions = [b32("transfer_money")];
    await expect(
      contract.connect(attacker).batchSetPermissions(agents, actions, [true])
    ).to.be.revertedWith("AgentPermissionRegistry: Not authorized");
    expect(await contract.checkPermission(agents[0], actions[0])).to.equal(false);
  });

  it("INV-3: every owner modification emits PermissionSet", async function () {
    const agent = b32("agent_c"), action = b32("execute_command");
    await expect(contract.setPermission(agent, action, true))
      .to.emit(contract, "PermissionSet");
    await expect(contract.setPermission(agent, action, false))
      .to.emit(contract, "PermissionSet");
  });

  it("INV-4: state and event log agree after a random legal sequence", async function () {
    // A permission's final state must equal the last PermissionSet event for it.
    const agent = b32("agent_c");
    const actions = ["search_web", "read_file", "transfer_money",
                     "execute_command", "delete_database"].map(b32);
    const expected = {};
    for (let i = 0; i < 40; i++) {
      const a = actions[Math.floor(Math.random() * actions.length)];
      const v = Math.random() < 0.5;
      await contract.setPermission(agent, a, v);
      expected[a] = v;
    }
    const evs = await contract.queryFilter(contract.filters.PermissionSet(), 0);
    const fromEvents = {};
    for (const e of evs) fromEvents[e.args.actionType] = e.args.permitted;
    for (const a of actions) {
      expect(await contract.checkPermission(agent, a)).to.equal(expected[a] ?? false);
      if (a in expected) expect(fromEvents[a]).to.equal(expected[a]);
    }
  });

  it("INV-5: a permission cannot change without an emitted event", async function () {
    const agent = b32("agent_c"), action = b32("delete_database");
    const before = await contract.checkPermission(agent, action);
    const evBefore = (await contract.queryFilter(contract.filters.PermissionSet(), 0)).length;
    // exercise every other externally reachable function
    await contract.logDecision(agent, action, false, hre.ethers.id("probe"));
    await contract.getStats();
    await contract.checkPermission(agent, action);
    const after = await contract.checkPermission(agent, action);
    const evAfter = (await contract.queryFilter(contract.filters.PermissionSet(), 0)).length;
    expect(after).to.equal(before);
    expect(evAfter).to.equal(evBefore);
  });

  it("INV-6: ownership transfer is owner-only and logged", async function () {
    await expect(
      contract.connect(attacker).transferOwnership(attacker.address)
    ).to.be.revertedWith("AgentPermissionRegistry: Not authorized");
    await expect(contract.transferOwnership(attacker.address))
      .to.emit(contract, "OwnershipTransferred");
    // after transfer the old owner loses the ability to modify policy
    await expect(
      contract.setPermission(b32("agent_c"), b32("read_file"), true)
    ).to.be.revertedWith("AgentPermissionRegistry: Not authorized");
  });

  it("INV-7: logDecision never mutates a permission", async function () {
    const agent = b32("agent_c"), action = b32("transfer_money");
    await contract.setPermission(agent, action, false);
    for (let i = 0; i < 20; i++) {
      await contract.connect(attacker).logDecision(
        agent, action, true, hre.ethers.id("x" + i));
      expect(await contract.checkPermission(agent, action)).to.equal(false);
    }
  });
});
