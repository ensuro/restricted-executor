const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { accessControlMessage, createCall, ownableContractFixture } = require("./fixtures");
const { PROPOSER_ROLE, CANCELLER_ROLE } = require("./constants");

const keccak256 = hre.web3.utils.keccak256;

describe("Ownable calls", () => {
  it("reverts if restrictedExecutor is not the owner", async () => {
    const { proposer, authorizer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      ownableContractFixture
    );
    const [randomAddress] = signers;

    const call = createCall(callReceiver.address, receiverEncode("function1", [keccak256("testing"), 280]));

    await restrictedExecutor.connect(proposer).create(call.target, call.value, call.data, call.salt, 1);

    await restrictedExecutor.connect(authorizer).grantRole(call.id, randomAddress.address);

    await expect(
      restrictedExecutor.connect(randomAddress).execute(call.target, call.value, call.data, call.salt)
    ).to.be.revertedWith("RestrictedExecutor: underlying transaction reverted");

    await callReceiver.transferOwnership(restrictedExecutor.address);

    const tx = restrictedExecutor.connect(randomAddress).execute(call.target, call.value, call.data, call.salt);
    await expect(tx).to.emit(callReceiver, "Function1Executed").withArgs(keccak256("testing"), 280);
    await expect(tx)
      .to.emit(restrictedExecutor, "CallExecuted")
      .withArgs(call.id, 0, call.target, call.value, call.data);
  });
});
