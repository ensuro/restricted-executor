const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { createAction, simpleContractFixture } = require("./fixtures");
const { PROPOSER_ROLE, AUTHORIZER_ROLE, ROLE1, DEFAULT_ADMIN_ROLE } = require("./constants");

const keccak256 = hre.web3.utils.keccak256;

const accessControlMessage = (address, role) =>
  `AccessControl: account ${address.toLowerCase()} is missing role ${role}`;

describe("Simple actions", () => {
  it("hashes actions", async () => {
    const { owner, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(simpleContractFixture);

    const action1 = createAction(callReceiver.address, receiverEncode("function1", [keccak256("testing"), 280]));
    let hash = await restrictedExecutor.hashAction(callReceiver.address, action1.value, action1.data, action1.salt);
    expect(hash).to.equal(action1.id);

    const action2 = createAction(callReceiver.address, receiverEncode("function2", [0, owner.address]));
    hash = await restrictedExecutor.hashAction(callReceiver.address, action2.value, action2.data, action2.salt);
    expect(hash).to.equal(action2.id);
  });

  it("only allows proposers to create new actions", async () => {
    const { proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    expect(await restrictedExecutor.hasRole(PROPOSER_ROLE, proposer.address)).to.be.true;

    const action = createAction(callReceiver.address, receiverEncode("function1", [keccak256("testing"), 280]));

    await expect(
      restrictedExecutor.connect(randomAddress).createAction(action.target, action.value, action.data, action.salt)
    ).to.be.revertedWith(accessControlMessage(randomAddress.address, PROPOSER_ROLE));

    await expect(
      restrictedExecutor.connect(proposer).createAction(action.target, action.value, action.data, action.salt)
    )
      .to.emit(restrictedExecutor, "ActionCreated")
      .withArgs(action.id, action.target, action.value, action.data, action.salt);
  });

  it("grants AUTHORIZER_ROLE admin permissions on new actions", async () => {
    const { proposer, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(simpleContractFixture);

    const data = receiverEncode("function1", [keccak256("testing"), 280]);
    const action = createAction(callReceiver.address, data);

    await expect(restrictedExecutor.connect(proposer).createAction(action.target, action.value, data, action.salt))
      .to.emit(restrictedExecutor, "RoleAdminChanged")
      .withArgs(action.id, DEFAULT_ADMIN_ROLE, AUTHORIZER_ROLE);
  });

  it("allows only authorized accounts to run actions", async () => {
    const { authorizer, proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    const action = createAction(callReceiver.address, receiverEncode("function1", [keccak256("testing"), 280]));

    await restrictedExecutor.connect(proposer).createAction(action.target, action.value, action.data, action.salt);

    await expect(
      restrictedExecutor.connect(randomAddress).execute(action.target, action.value, action.data, action.salt)
    ).to.be.revertedWith(accessControlMessage(randomAddress.address, action.id));

    await expect(restrictedExecutor.connect(authorizer).grantRole(action.id, randomAddress.address))
      .to.emit(restrictedExecutor, "RoleGranted")
      .withArgs(action.id, randomAddress.address, authorizer.address);

    await expect(
      restrictedExecutor.connect(randomAddress).execute(action.target, action.value, action.data, action.salt)
    )
      .to.emit(callReceiver, "Function1Executed")
      .withArgs(keccak256("testing"), 280);
  });

  it("allows open actions", async () => {
    const { authorizer, proposer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    const action = createAction(callReceiver.address, receiverEncode("function1", [keccak256("openActions"), 280]));

    await restrictedExecutor.connect(proposer).createAction(action.target, action.value, action.data, action.salt);

    await restrictedExecutor.connect(authorizer).grantRole(action.id, hre.ethers.constants.AddressZero);

    await expect(
      restrictedExecutor.connect(randomAddress).execute(action.target, action.value, action.data, action.salt)
    )
      .to.emit(callReceiver, "Function1Executed")
      .withArgs(keccak256("openActions"), 280);
  });

  it("allows only registered actions to run", async () => {
    const { owner, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    const action = createAction(callReceiver.address, receiverEncode("function1", [keccak256("testing"), 280]));

    // owner grants action permissions (authorizer has not been granted admin on the action's role because the action was never created)
    await restrictedExecutor.connect(owner).grantRole(action.id, randomAddress.address);

    await expect(
      restrictedExecutor.connect(randomAddress).execute(action.target, action.value, action.data, action.salt)
    ).to.be.revertedWith("RestrictedExecutor: unkwnown action");
  });
});
