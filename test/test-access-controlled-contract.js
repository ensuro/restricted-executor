const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { createAction, accessControlledFixture } = require("./fixtures");

const { ROLE2 } = require("./constants");

const keccak256 = hre.web3.utils.keccak256;

describe("AccessControlled actions", () => {
  it("reverts if restricted executor contract has not been granted permissions on the target contract", async () => {
    const { authorizer, proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      accessControlledFixture
    );
    const [randomAddress] = signers;

    const action1 = createAction(callReceiver.address, receiverEncode("role1Function", [keccak256("testing"), 280]));
    const action2 = createAction(callReceiver.address, receiverEncode("role2Function", [0, randomAddress.address]));

    await restrictedExecutor.connect(proposer).createAction(action1.target, action1.value, action1.data, action1.salt);
    await restrictedExecutor.connect(authorizer).grantRole(action1.id, randomAddress.address);

    await restrictedExecutor.connect(proposer).createAction(action2.target, action2.value, action2.data, action2.salt);
    await restrictedExecutor.connect(authorizer).grantRole(action2.id, randomAddress.address);

    await callReceiver.grantRole(ROLE2, restrictedExecutor.address);

    await expect(
      restrictedExecutor.connect(randomAddress).execute(action1.target, action1.value, action1.data, action1.salt)
    ).to.be.revertedWith("RestrictedExecutor: underlying transaction reverted");

    await expect(
      restrictedExecutor.connect(randomAddress).execute(action2.target, action2.value, action2.data, action2.salt)
    )
      .to.emit(callReceiver, "Role2FunctionExecuted")
      .withArgs(0, randomAddress.address);
  });
});
