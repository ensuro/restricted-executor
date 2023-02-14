const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { createCall, accessControlledFixture } = require("./fixtures");

const { ROLE2 } = require("./constants");

const keccak256 = hre.web3.utils.keccak256;

describe("AccessControlled calls", () => {
  it("reverts if restricted executor contract has not been granted permissions on the target contract", async () => {
    const { authorizer, proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      accessControlledFixture
    );
    const [randomAddress] = signers;

    const call1 = createCall(callReceiver.address, receiverEncode("role1Function", [keccak256("testing"), 280]));
    const call2 = createCall(callReceiver.address, receiverEncode("role2Function", [0, randomAddress.address]));

    await restrictedExecutor.connect(proposer).create(call1.target, call1.value, call1.data, call1.salt);
    await restrictedExecutor.connect(authorizer).grantRole(call1.id, randomAddress.address);

    await restrictedExecutor.connect(proposer).create(call2.target, call2.value, call2.data, call2.salt);
    await restrictedExecutor.connect(authorizer).grantRole(call2.id, randomAddress.address);

    await callReceiver.grantRole(ROLE2, restrictedExecutor.address);

    await expect(
      restrictedExecutor.connect(randomAddress).execute(call1.target, call1.value, call1.data, call1.salt)
    ).to.be.revertedWith("RestrictedExecutor: underlying transaction reverted");

    await expect(restrictedExecutor.connect(randomAddress).execute(call2.target, call2.value, call2.data, call2.salt))
      .to.emit(callReceiver, "Role2FunctionExecuted")
      .withArgs(0, randomAddress.address);
  });
});
