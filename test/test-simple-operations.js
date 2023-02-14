const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { accessControlMessage, createCall, simpleContractFixture } = require("./fixtures");
const { PROPOSER_ROLE, AUTHORIZER_ROLE, DEFAULT_ADMIN_ROLE } = require("./constants");

const keccak256 = hre.web3.utils.keccak256;

describe("Simple calls", () => {
  it("hashes calls", async () => {
    const { owner, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(simpleContractFixture);

    const call1 = createCall(callReceiver.address, receiverEncode("function1", [keccak256("testing"), 280]));
    let hash = await restrictedExecutor.hashCall(callReceiver.address, call1.value, call1.data, call1.salt);
    expect(hash).to.equal(call1.id);

    const call2 = createCall(callReceiver.address, receiverEncode("function2", [0, owner.address]));
    hash = await restrictedExecutor.hashCall(callReceiver.address, call2.value, call2.data, call2.salt);
    expect(hash).to.equal(call2.id);
  });

  it("only allows proposers to create new operations", async () => {
    const { proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    expect(await restrictedExecutor.hasRole(PROPOSER_ROLE, proposer.address)).to.be.true;

    const call = createCall(callReceiver.address, receiverEncode("function1", [keccak256("testing"), 280]));

    await expect(
      restrictedExecutor.connect(randomAddress).create(call.target, call.value, call.data, call.salt)
    ).to.be.revertedWith(accessControlMessage(randomAddress.address, PROPOSER_ROLE));

    await expect(restrictedExecutor.connect(proposer).create(call.target, call.value, call.data, call.salt))
      .to.emit(restrictedExecutor, "CallCreated")
      .withArgs(call.id, 0, call.target, call.value, call.data, call.salt);
  });

  it("grants AUTHORIZER_ROLE admin permissions on new operations", async () => {
    const { proposer, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(simpleContractFixture);

    const data = receiverEncode("function1", [keccak256("testing"), 280]);
    const call = createCall(callReceiver.address, data);

    await expect(restrictedExecutor.connect(proposer).create(call.target, call.value, data, call.salt))
      .to.emit(restrictedExecutor, "RoleAdminChanged")
      .withArgs(call.id, DEFAULT_ADMIN_ROLE, AUTHORIZER_ROLE);
  });

  it("allows only authorized accounts to execute operations", async () => {
    const { authorizer, proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    const call = createCall(callReceiver.address, receiverEncode("function1", [keccak256("testing"), 280]));

    await restrictedExecutor.connect(proposer).create(call.target, call.value, call.data, call.salt);

    await expect(
      restrictedExecutor.connect(randomAddress).execute(call.target, call.value, call.data, call.salt)
    ).to.be.revertedWith(accessControlMessage(randomAddress.address, call.id));

    await expect(restrictedExecutor.connect(authorizer).grantRole(call.id, randomAddress.address))
      .to.emit(restrictedExecutor, "RoleGranted")
      .withArgs(call.id, randomAddress.address, authorizer.address);

    await expect(restrictedExecutor.connect(randomAddress).execute(call.target, call.value, call.data, call.salt))
      .to.emit(callReceiver, "Function1Executed")
      .withArgs(keccak256("testing"), 280);
  });

  it("allows open operations", async () => {
    const { authorizer, proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    const call = createCall(callReceiver.address, receiverEncode("function1", [keccak256("openActions"), 280]));

    await restrictedExecutor.connect(proposer).create(call.target, call.value, call.data, call.salt);

    await restrictedExecutor.connect(authorizer).grantRole(call.id, hre.ethers.constants.AddressZero);

    await expect(restrictedExecutor.connect(randomAddress).execute(call.target, call.value, call.data, call.salt))
      .to.emit(callReceiver, "Function1Executed")
      .withArgs(keccak256("openActions"), 280);
  });

  it("allows only registered operations to run", async () => {
    const { owner, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    const call = createCall(callReceiver.address, receiverEncode("function1", [keccak256("testing"), 280]));

    // owner grants operation permissions (authorizer has not been granted admin on the operation's role because the operation was never created)
    await restrictedExecutor.connect(owner).grantRole(call.id, randomAddress.address);

    await expect(
      restrictedExecutor.connect(randomAddress).execute(call.target, call.value, call.data, call.salt)
    ).to.be.revertedWith("RestrictedExecutor: unknown operation");
  });
});
