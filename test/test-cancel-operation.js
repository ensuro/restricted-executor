const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { accessControlMessage, createCall, simpleContractFixture } = require("./fixtures");
const { PROPOSER_ROLE, CANCELLER_ROLE } = require("./constants");

const keccak256 = hre.web3.utils.keccak256;

describe("Operation cancellation", () => {
  it("allows only CANCELLER to cancel operations", async () => {
    const { proposer, canceller, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    expect(await restrictedExecutor.hasRole(PROPOSER_ROLE, proposer.address)).to.be.true;

    const call = createCall(callReceiver.address, receiverEncode("function1", [keccak256("testing"), 280]));

    await restrictedExecutor.connect(proposer).create(call.target, call.value, call.data, call.salt, 1);

    expect(await restrictedExecutor.getRemainingExecutions(call.id)).to.equal(1);

    await expect(restrictedExecutor.connect(randomAddress).cancel(call.id)).to.be.revertedWith(
      accessControlMessage(randomAddress.address, CANCELLER_ROLE)
    );

    await expect(restrictedExecutor.connect(canceller).cancel(call.id))
      .to.emit(restrictedExecutor, "Cancelled")
      .withArgs(call.id);

    expect(await restrictedExecutor.getRemainingExecutions(call.id)).to.equal(0);

    await expect(restrictedExecutor.connect(canceller).cancel(call.id)).to.be.revertedWith(
      "RestrictedExecutor: unknown operation"
    );
  });
});
