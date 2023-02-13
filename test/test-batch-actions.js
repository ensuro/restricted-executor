const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { accessControlMessage, createActionBatch, simpleContractFixture } = require("./fixtures");
const { PROPOSER_ROLE, AUTHORIZER_ROLE, DEFAULT_ADMIN_ROLE } = require("./constants");

const keccak256 = hre.web3.utils.keccak256;

describe("Batch actions", () => {
  it("hashes batch action", async () => {
    const { owner, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(simpleContractFixture);

    const actionBatch = createActionBatch(
      [callReceiver.address, callReceiver.address],
      [receiverEncode("function1", [keccak256("testing"), 280]), receiverEncode("function2", [0, owner.address])]
    );
    const hash = await restrictedExecutor.hashActionBatch(
      actionBatch.targets,
      actionBatch.values,
      actionBatch.payloads,
      actionBatch.salt
    );
    expect(hash).to.equal(actionBatch.id);
  });

  it("only allows PROPOSER_ROLE to create action batches", async () => {
    const { proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    expect(await restrictedExecutor.hasRole(PROPOSER_ROLE, proposer.address)).to.be.true;

    const actionBatch = createActionBatch(
      [callReceiver.address, callReceiver.address],
      [
        receiverEncode("function1", [keccak256("batch action"), 280]),
        receiverEncode("function2", [0, randomAddress.address]),
      ]
    );

    await expect(
      restrictedExecutor
        .connect(randomAddress)
        .createActionBatch(actionBatch.targets, actionBatch.values, actionBatch.payloads, actionBatch.salt)
    ).to.be.revertedWith(accessControlMessage(randomAddress.address, PROPOSER_ROLE));

    const tx = restrictedExecutor
      .connect(proposer)
      .createActionBatch(actionBatch.targets, actionBatch.values, actionBatch.payloads, actionBatch.salt);

    await expect(tx)
      .to.emit(restrictedExecutor, "ActionCreated")
      .withArgs(
        actionBatch.id,
        actionBatch.targets[0],
        actionBatch.values[0],
        actionBatch.payloads[0],
        actionBatch.salt
      );

    await expect(tx)
      .to.emit(restrictedExecutor, "ActionCreated")
      .withArgs(
        actionBatch.id,
        actionBatch.targets[1],
        actionBatch.values[1],
        actionBatch.payloads[1],
        actionBatch.salt
      );
  });

  it("grants AUTHORIZER_ROLE admin permissions on new actions", async () => {
    const { proposer, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(simpleContractFixture);

    const actionBatch = createActionBatch(
      [callReceiver.address, callReceiver.address],
      [
        receiverEncode("function1", [keccak256("authorizer test"), 280]),
        receiverEncode("function2", [0, callReceiver.address]),
      ]
    );

    await expect(
      restrictedExecutor
        .connect(proposer)
        .createActionBatch(actionBatch.targets, actionBatch.values, actionBatch.payloads, actionBatch.salt)
    )
      .to.emit(restrictedExecutor, "RoleAdminChanged")
      .withArgs(actionBatch.id, DEFAULT_ADMIN_ROLE, AUTHORIZER_ROLE);
  });

  it("allows only authorized accounts to execute actions", async () => {
    const { authorizer, proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    const actionBatch = createActionBatch(
      [callReceiver.address, callReceiver.address],
      [
        receiverEncode("function1", [keccak256("batch action"), 280]),
        receiverEncode("function2", [0, randomAddress.address]),
      ]
    );

    await restrictedExecutor
      .connect(proposer)
      .createActionBatch(actionBatch.targets, actionBatch.values, actionBatch.payloads, actionBatch.salt);

    await expect(
      restrictedExecutor
        .connect(randomAddress)
        .executeBatch(actionBatch.targets, actionBatch.values, actionBatch.payloads, actionBatch.salt)
    ).to.be.revertedWith(accessControlMessage(randomAddress.address, actionBatch.id));

    await expect(restrictedExecutor.connect(authorizer).grantRole(actionBatch.id, randomAddress.address))
      .to.emit(restrictedExecutor, "RoleGranted")
      .withArgs(actionBatch.id, randomAddress.address, authorizer.address);

    const tx = restrictedExecutor
      .connect(randomAddress)
      .executeBatch(actionBatch.targets, actionBatch.values, actionBatch.payloads, actionBatch.salt);

    await expect(tx).to.emit(callReceiver, "Function1Executed").withArgs(keccak256("batch action"), 280);
    await expect(tx).to.emit(callReceiver, "Function2Executed").withArgs(0, randomAddress.address);
  });
});
