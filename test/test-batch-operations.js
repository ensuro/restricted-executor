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
        .createBatch(
          callBatch.targets,
          callBatch.values,
          callBatch.payloads,
          callBatch.salt,
          hre.ethers.constants.MaxUint256
        )
    ).to.be.revertedWith(accessControlMessage(randomAddress.address, PROPOSER_ROLE));

    const tx = restrictedExecutor
      .connect(proposer)
      .createBatch(
        callBatch.targets,
        callBatch.values,
        callBatch.payloads,
        callBatch.salt,
        hre.ethers.constants.MaxUint256
      );

    await expect(tx)
      .to.emit(restrictedExecutor, "CallCreated")
      .withArgs(
        callBatch.id,
        0,
        callBatch.targets[0],
        callBatch.values[0],
        callBatch.payloads[0],
        callBatch.salt,
        hre.ethers.constants.MaxUint256
      );

    await expect(tx)
      .to.emit(restrictedExecutor, "CallCreated")
      .withArgs(
        callBatch.id,
        1,
        callBatch.targets[1],
        callBatch.values[1],
        callBatch.payloads[1],
        callBatch.salt,
        hre.ethers.constants.MaxUint256
      );
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
        .createBatch(
          callBatch.targets,
          callBatch.values,
          callBatch.payloads,
          callBatch.salt,
          hre.ethers.constants.MaxUint256
        )
    )
      .to.emit(restrictedExecutor, "RoleAdminChanged")
      .withArgs(callBatch.id, DEFAULT_ADMIN_ROLE, AUTHORIZER_ROLE);

    expect(await restrictedExecutor.getRoleAdmin(callBatch.id)).to.equal(AUTHORIZER_ROLE);
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
      .createBatch(
        callBatch.targets,
        callBatch.values,
        callBatch.payloads,
        callBatch.salt,
        hre.ethers.constants.MaxUint256
      );

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

    await expect(tx)
      .to.emit(restrictedExecutor, "CallExecuted")
      .withArgs(callBatch.id, 0, callBatch.targets[0], callBatch.values[0], callBatch.payloads[0]);
    await expect(tx)
      .to.emit(restrictedExecutor, "CallExecuted")
      .withArgs(callBatch.id, 1, callBatch.targets[1], callBatch.values[1], callBatch.payloads[1]);
  });

  it("limits the number of executions per operation", async () => {
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
      .createBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt, 2);
    await restrictedExecutor.connect(authorizer).grantRole(callBatch.id, randomAddress.address);

    expect(await restrictedExecutor.getRemainingExecutions(callBatch.id)).to.equal(2);

    await restrictedExecutor
      .connect(randomAddress)
      .executeBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt);

    expect(await restrictedExecutor.getRemainingExecutions(callBatch.id)).to.equal(1);

    await restrictedExecutor
      .connect(randomAddress)
      .executeBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt);

    expect(await restrictedExecutor.getRemainingExecutions(callBatch.id)).to.equal(0);

    await expect(
      restrictedExecutor
        .connect(randomAddress)
        .executeBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt)
    ).to.be.revertedWith("RestrictedExecutor: unknown operation");
  });

  it("allows operations to have an infinite number of executions", async () => {
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
      .createBatch(
        callBatch.targets,
        callBatch.values,
        callBatch.payloads,
        callBatch.salt,
        hre.ethers.constants.MaxUint256
      );
    await restrictedExecutor.connect(authorizer).grantRole(callBatch.id, randomAddress.address);

    expect(await restrictedExecutor.getRemainingExecutions(callBatch.id)).to.equal(hre.ethers.constants.MaxUint256);
    await restrictedExecutor
      .connect(randomAddress)
      .executeBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt);

    expect(await restrictedExecutor.getRemainingExecutions(callBatch.id)).to.equal(hre.ethers.constants.MaxUint256);
  });

  it("does not allow creating operations with no execution allowance", async () => {
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

    await expect(
      restrictedExecutor
        .connect(proposer)
        .createBatch(callBatch.targets, callBatch.values, callBatch.payloads, callBatch.salt, 0)
    ).to.be.revertedWith("RestrictedExecutor: invalid maxExecutions value");
  });
});
