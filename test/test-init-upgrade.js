const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { createCall, createBatch, simpleContractFixture, accessControlMessage } = require("./fixtures");
const { UPGRADER_ROLE } = require("./constants");

describe("Initialization", () => {
  it("is not allowed once the contract has been initialized", async () => {
    const { proposer, authorizer, restrictedExecutor } = await loadFixture(simpleContractFixture);

    await expect(restrictedExecutor.initialize([authorizer.address], [proposer.address])).to.be.revertedWith(
      "Initializable: contract is already initialized"
    );
  });
});

describe("Upgrade", () => {
  it("is only allowed for UPGRADER_ROLE", async () => {
    const { owner, restrictedExecutor: proxyContract, RestrictedExecutor } = await loadFixture(simpleContractFixture);

    const newImplementation = await RestrictedExecutor.deploy();

    // Not even the owner can upgrade
    await expect(proxyContract.connect(owner).upgradeTo(newImplementation.address)).to.be.revertedWith(
      accessControlMessage(owner.address, UPGRADER_ROLE)
    );

    // But she can grant herself the upgrader role
    await proxyContract.grantRole(UPGRADER_ROLE, owner.address);

    // And then upgrade
    await expect(proxyContract.connect(owner).upgradeTo(newImplementation.address)).not.to.be.reverted;
  });
});
