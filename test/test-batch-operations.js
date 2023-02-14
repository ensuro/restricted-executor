const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { accessControlMessage, createBatch, simpleContractFixture } = require("./fixtures");
const { PROPOSER_ROLE, AUTHORIZER_ROLE, DEFAULT_ADMIN_ROLE } = require("./constants");

const keccak256 = hre.web3.utils.keccak256;

describe("Batch operations", () => {
  it("hashes call batch", async () => {
    const { owner, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(simpleContractFixture);

    const callBatch = createBatch(
      [callReceiver.address, callReceiver.address],
      [receiverEncode("function1", [keccak256("testing"), 280]), receiverEncode("function2", [0, owner.address])]
    );
    const hash = await restrictedExecutor.hashCallBatch(
      callBatch.targets,
      callBatch.values,
      callBatch.payloads,
      callBatch.salt
    );
    expect(hash).to.equal(callBatch.id);
  });

  it("only allows PROPOSER_ROLE to create call batches", async () => {
    const { proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    expect(await restrictedExecutor.hasRole(PROPOSER_ROLE, proposer.address)).to.be.true;

    const callBatch = createBatch(
      [callReceiver.address, callReceiver.address],
      [
        receiverEncode("function1", [keccak256("call batch"), 280]),
        receiverEncode("function2", [0, randomAddress.address]),
      ]
    );

    await expect(
      restrictedExecutor
        .connect(randomAddress)
        .createBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt)
    ).to.be.revertedWith(accessControlMessage(randomAddress.address, PROPOSER_ROLE));

    const tx = restrictedExecutor
      .connect(proposer)
      .createBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt);

    await expect(tx)
      .to.emit(restrictedExecutor, "CallCreated")
      .withArgs(callBatch.id, 0, callBatch.targets[0], callBatch.values[0], callBatch.payloads[0], callBatch.salt);

    await expect(tx)
      .to.emit(restrictedExecutor, "CallCreated")
      .withArgs(callBatch.id, 1, callBatch.targets[1], callBatch.values[1], callBatch.payloads[1], callBatch.salt);
  });

  it("grants AUTHORIZER_ROLE admin permissions on new operations", async () => {
    const { proposer, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(simpleContractFixture);

    const callBatch = createBatch(
      [callReceiver.address, callReceiver.address],
      [
        receiverEncode("function1", [keccak256("authorizer test"), 280]),
        receiverEncode("function2", [0, callReceiver.address]),
      ]
    );

    await expect(
      restrictedExecutor
        .connect(proposer)
        .createBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt)
    )
      .to.emit(restrictedExecutor, "RoleAdminChanged")
      .withArgs(callBatch.id, DEFAULT_ADMIN_ROLE, AUTHORIZER_ROLE);
  });

  it("allows only authorized accounts to execute operations", async () => {
    const { authorizer, proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    const callBatch = createBatch(
      [callReceiver.address, callReceiver.address],
      [
        receiverEncode("function1", [keccak256("call batch"), 280]),
        receiverEncode("function2", [0, randomAddress.address]),
      ]
    );

    await restrictedExecutor
      .connect(proposer)
      .createBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt);

    await expect(
      restrictedExecutor
        .connect(randomAddress)
        .executeBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt)
    ).to.be.revertedWith(accessControlMessage(randomAddress.address, callBatch.id));

    await expect(restrictedExecutor.connect(authorizer).grantRole(callBatch.id, randomAddress.address))
      .to.emit(restrictedExecutor, "RoleGranted")
      .withArgs(callBatch.id, randomAddress.address, authorizer.address);

    const tx = restrictedExecutor
      .connect(randomAddress)
      .executeBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt);

    await expect(tx).to.emit(callReceiver, "Function1Executed").withArgs(keccak256("call batch"), 280);
    await expect(tx).to.emit(callReceiver, "Function2Executed").withArgs(0, randomAddress.address);
  });
});
