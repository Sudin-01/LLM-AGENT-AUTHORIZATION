// test/AgentPermissionRegistry.test.js
const { expect } = require("chai");
const { ethers }  = require("hardhat");

describe("AgentPermissionRegistry", function () {
  let registry, owner, addr1, addr2;

  // Helper: convert string → bytes32
  const b32 = (s) => ethers.encodeBytes32String(s.substring(0, 31));

  beforeEach(async () => {
    [owner, addr1, addr2] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("AgentPermissionRegistry");
    registry = await Factory.deploy();
    await registry.waitForDeployment();
  });

  // ── Deployment ─────────────────────────────────────────────────────────────
  describe("Deployment", () => {
    it("sets the deployer as owner", async () => {
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("initializes totalDecisions to 0", async () => {
      const [decisions] = await registry.getStats();
      expect(decisions).to.equal(0n);
    });
  });

  // ── setPermission ──────────────────────────────────────────────────────────
  describe("setPermission", () => {
    it("allows owner to set a permission", async () => {
      await registry.setPermission(b32("agent_a"), b32("search_web"), true);
      expect(await registry.checkPermission(b32("agent_a"), b32("search_web"))).to.be.true;
    });

    it("defaults to false for unset permissions", async () => {
      expect(await registry.checkPermission(b32("agent_x"), b32("delete_database"))).to.be.false;
    });

    it("allows owner to revoke a previously granted permission", async () => {
      await registry.setPermission(b32("agent_a"), b32("transfer_money"), true);
      await registry.setPermission(b32("agent_a"), b32("transfer_money"), false);
      expect(await registry.checkPermission(b32("agent_a"), b32("transfer_money"))).to.be.false;
    });

    it("emits PermissionSet event", async () => {
      await expect(
        registry.setPermission(b32("agent_a"), b32("search_web"), true)
      ).to.emit(registry, "PermissionSet")
       .withArgs(b32("agent_a"), b32("search_web"), true, expect.anything());
    });

    it("reverts if non-owner calls setPermission", async () => {
      await expect(
        registry.connect(addr1).setPermission(b32("agent_a"), b32("search_web"), true)
      ).to.be.revertedWith("AgentPermissionRegistry: Not authorized");
    });
  });

  // ── batchSetPermissions ────────────────────────────────────────────────────
  describe("batchSetPermissions", () => {
    it("sets multiple permissions in a single transaction", async () => {
      const agents  = [b32("agent_a"), b32("agent_a"), b32("agent_a")];
      const actions = [b32("search_web"), b32("read_file"), b32("delete_database")];
      const perms   = [true, true, false];

      await registry.batchSetPermissions(agents, actions, perms);

      expect(await registry.checkPermission(b32("agent_a"), b32("search_web"))).to.be.true;
      expect(await registry.checkPermission(b32("agent_a"), b32("read_file"))).to.be.true;
      expect(await registry.checkPermission(b32("agent_a"), b32("delete_database"))).to.be.false;
    });

    it("reverts on array length mismatch", async () => {
      await expect(
        registry.batchSetPermissions(
          [b32("agent_a"), b32("agent_b")],
          [b32("search_web")],
          [true]
        )
      ).to.be.revertedWith("Array length mismatch");
    });

    it("reverts if non-owner calls batchSetPermissions", async () => {
      await expect(
        registry.connect(addr1).batchSetPermissions([], [], [])
      ).to.be.revertedWith("AgentPermissionRegistry: Not authorized");
    });
  });

  // ── checkPermission ────────────────────────────────────────────────────────
  describe("checkPermission", () => {
    beforeEach(async () => {
      await registry.batchSetPermissions(
        [b32("agent_a"), b32("agent_a"), b32("agent_a")],
        [b32("search_web"), b32("read_file"), b32("transfer_money")],
        [true, true, false]
      );
    });

    it("returns true for explicitly allowed action", async () => {
      expect(await registry.checkPermission(b32("agent_a"), b32("search_web"))).to.be.true;
    });

    it("returns false for explicitly denied action", async () => {
      expect(await registry.checkPermission(b32("agent_a"), b32("transfer_money"))).to.be.false;
    });

    it("returns false for unknown agent", async () => {
      expect(await registry.checkPermission(b32("unknown_agent"), b32("search_web"))).to.be.false;
    });

    it("is callable by any address (view function)", async () => {
      // Non-owner can read permissions
      expect(
        await registry.connect(addr1).checkPermission(b32("agent_a"), b32("search_web"))
      ).to.be.true;
    });
  });

  // ── logDecision ───────────────────────────────────────────────────────────
  describe("logDecision", () => {
    it("emits DecisionLogged event with correct parameters", async () => {
      const reqHash = ethers.keccak256(ethers.toUtf8Bytes("test-request-payload"));
      await expect(
        registry.logDecision(b32("agent_a"), b32("search_web"), true, reqHash)
      ).to.emit(registry, "DecisionLogged")
       .withArgs(b32("agent_a"), b32("search_web"), true, reqHash, expect.anything(), owner.address);
    });

    it("increments totalDecisions", async () => {
      const reqHash = ethers.keccak256(ethers.toUtf8Bytes("req1"));
      await registry.logDecision(b32("agent_a"), b32("search_web"), true, reqHash);
      await registry.logDecision(b32("agent_a"), b32("delete_database"), false, reqHash);
      const [decisions] = await registry.getStats();
      expect(decisions).to.equal(2n);
    });

    it("increments totalDenials only for denied decisions", async () => {
      const reqHash = ethers.keccak256(ethers.toUtf8Bytes("req1"));
      await registry.logDecision(b32("agent_a"), b32("search_web"), true, reqHash);  // allowed
      await registry.logDecision(b32("agent_a"), b32("delete_database"), false, reqHash); // denied
      await registry.logDecision(b32("agent_a"), b32("transfer_money"), false, reqHash);  // denied
      const [decisions, denials] = await registry.getStats();
      expect(decisions).to.equal(3n);
      expect(denials).to.equal(2n);
    });

    it("can be called by any address (open audit logging)", async () => {
      const reqHash = ethers.keccak256(ethers.toUtf8Bytes("req"));
      await expect(
        registry.connect(addr1).logDecision(b32("agent_a"), b32("search_web"), true, reqHash)
      ).to.not.be.reverted;
    });
  });

  // ── getStats ──────────────────────────────────────────────────────────────
  describe("getStats", () => {
    it("returns zeros before any decisions", async () => {
      const [d, dn] = await registry.getStats();
      expect(d).to.equal(0n);
      expect(dn).to.equal(0n);
    });

    it("correctly tracks decisions and denials over many calls", async () => {
      const reqHash = ethers.keccak256(ethers.toUtf8Bytes("x"));
      for (let i = 0; i < 5; i++) {
        await registry.logDecision(b32("agent_a"), b32("search_web"), true, reqHash);
      }
      for (let i = 0; i < 3; i++) {
        await registry.logDecision(b32("agent_a"), b32("delete_database"), false, reqHash);
      }
      const [d, dn] = await registry.getStats();
      expect(d).to.equal(8n);
      expect(dn).to.equal(3n);
    });
  });

  // ── transferOwnership ─────────────────────────────────────────────────────
  describe("transferOwnership", () => {
    it("transfers ownership to new address", async () => {
      await registry.transferOwnership(addr1.address);
      expect(await registry.owner()).to.equal(addr1.address);
    });

    it("emits OwnershipTransferred event", async () => {
      await expect(registry.transferOwnership(addr1.address))
        .to.emit(registry, "OwnershipTransferred")
        .withArgs(owner.address, addr1.address);
    });

    it("reverts on zero address", async () => {
      await expect(registry.transferOwnership(ethers.ZeroAddress))
        .to.be.revertedWith("Zero address");
    });

    it("reverts if non-owner tries to transfer ownership", async () => {
      await expect(registry.connect(addr1).transferOwnership(addr2.address))
        .to.be.revertedWith("AgentPermissionRegistry: Not authorized");
    });

    it("allows new owner to set permissions after transfer", async () => {
      await registry.transferOwnership(addr1.address);
      await registry.connect(addr1).setPermission(b32("agent_x"), b32("search_web"), true);
      expect(await registry.checkPermission(b32("agent_x"), b32("search_web"))).to.be.true;
    });
  });

  // ── Security: policy tamper-resistance ────────────────────────────────────
  describe("Security properties", () => {
    it("cannot be modified by non-owner regardless of permission state", async () => {
      await registry.setPermission(b32("agent_a"), b32("delete_database"), false);
      // Attacker tries to escalate privilege
      await expect(
        registry.connect(addr2).setPermission(b32("agent_a"), b32("delete_database"), true)
      ).to.be.revertedWith("AgentPermissionRegistry: Not authorized");
      // Verify state unchanged
      expect(await registry.checkPermission(b32("agent_a"), b32("delete_database"))).to.be.false;
    });

    it("policy changes are reflected immediately in subsequent checks", async () => {
      await registry.setPermission(b32("agent_a"), b32("transfer_money"), true);
      expect(await registry.checkPermission(b32("agent_a"), b32("transfer_money"))).to.be.true;
      await registry.setPermission(b32("agent_a"), b32("transfer_money"), false);
      expect(await registry.checkPermission(b32("agent_a"), b32("transfer_money"))).to.be.false;
    });

    it("agent isolation: agent_a permissions do not affect agent_b", async () => {
      await registry.setPermission(b32("agent_a"), b32("delete_database"), true);
      expect(await registry.checkPermission(b32("agent_b"), b32("delete_database"))).to.be.false;
    });
  });
});
