const { time, loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const { expect } = require("chai");
const hre = require("hardhat");

const keccak256 = hre.web3.utils.keccak256;

describe("RestrictedExecutor", () => {
  const PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
  const AUTHORIZER_ROLE = keccak256("AUTHORIZER_ROLE");
  const ROLE1 = keccak256("ROLE1");
  const DEFAULT_ADMIN_ROLE = hre.ethers.utils.hexZeroPad("0x0", 32);

  it("hashes operations", async () => {
    const [owner, wallet1, wallet2] = await hre.ethers.getSigners();
    const RestrictedExecutor = await hre.ethers.getContractFactory("RestrictedExecutor");
    const re = await hre.upgrades.deployProxy(RestrictedExecutor, [[], []]);

    const AccessControlledContract = await hre.ethers.getContractFactory("AccessControlledContract");
    const callReceiver = await AccessControlledContract.deploy();

    const salt = hre.ethers.utils.hexZeroPad("0x0", 32);
    const data1 = callReceiver.interface.encodeFunctionData("role1Function", [keccak256("testing"), 280]);
    let hash = await re.hashOperation(callReceiver.address, 0, data1, salt);
    let { id: expectedHash } = createAction(callReceiver.address, 0, data1, salt);
    expect(hash).to.equal(expectedHash);

    const data2 = callReceiver.interface.encodeFunctionData("role2Function", [0, owner.address]);
    hash = await re.hashOperation(callReceiver.address, 0, data2, salt);
    expectedHash = createAction(callReceiver.address, 0, data2, salt).id;
    expect(hash).to.equal(expectedHash);
  });

  it("only allows proposers to create new actions", async () => {
    const [owner, authorizer, proposer, randomAddress] = await hre.ethers.getSigners();

    const RestrictedExecutor = await hre.ethers.getContractFactory("RestrictedExecutor");
    const re = await hre.upgrades.deployProxy(RestrictedExecutor, [[authorizer.address], [proposer.address]]);

    expect(await re.hasRole(PROPOSER_ROLE, proposer.address)).to.be.true;

    const AccessControlledContract = await hre.ethers.getContractFactory("AccessControlledContract");
    const callReceiver = await AccessControlledContract.deploy();

    const action = createAction(
      callReceiver.address,
      0,
      callReceiver.interface.encodeFunctionData("role1Function", [keccak256("testing"), 280]),
      hre.ethers.utils.hexZeroPad("0x0", 32)
    );

    await expect(
      re.connect(randomAddress).createAction(action.target, action.value, action.data, action.salt)
    ).to.be.revertedWith(
      `AccessControl: account ${randomAddress.address.toLowerCase()} is missing role ${PROPOSER_ROLE}`
    );

    await expect(re.connect(proposer).createAction(action.target, action.value, action.data, action.salt))
      .to.emit(re, "ActionCreated")
      .withArgs(action.id, action.target, action.value, action.data, action.salt);
  });

  it("grants AUTHORIZER permissions on new actions", async () => {
    const [owner, authorizer, proposer, randomAddress] = await hre.ethers.getSigners();
    const RestrictedExecutor = await hre.ethers.getContractFactory("RestrictedExecutor");
    const re = await hre.upgrades.deployProxy(RestrictedExecutor, [[authorizer.address], [proposer.address]]);

    const AccessControlledContract = await hre.ethers.getContractFactory("AccessControlledContract");
    const callReceiver = await AccessControlledContract.deploy();

    const data = callReceiver.interface.encodeFunctionData("role1Function", [keccak256("testing"), 280]);
    const action = createAction(callReceiver.address, 0, data, hre.ethers.utils.hexZeroPad("0x0", 32));

    await expect(re.connect(proposer).createAction(action.target, 0, data, action.salt))
      .to.emit(re, "RoleAdminChanged")
      .withArgs(action.id, DEFAULT_ADMIN_ROLE, AUTHORIZER_ROLE);
  });

  it("allows only authorized accounts to run actions", async () => {
    const [owner, authorizer, proposer, randomAddress] = await hre.ethers.getSigners();
    const RestrictedExecutor = await hre.ethers.getContractFactory("RestrictedExecutor");
    const re = await hre.upgrades.deployProxy(RestrictedExecutor, [[authorizer.address], [proposer.address]]);

    const AccessControlledContract = await hre.ethers.getContractFactory("AccessControlledContract");
    const callReceiver = await AccessControlledContract.deploy();
    await callReceiver.grantRole(ROLE1, re.address);

    const action = createAction(
      callReceiver.address,
      0,
      callReceiver.interface.encodeFunctionData("role1Function", [keccak256("testing"), 280]),
      hre.ethers.utils.hexZeroPad("0x0", 32)
    );

    await re.connect(proposer).createAction(action.target, action.value, action.data, action.salt);

    await expect(
      re.connect(randomAddress).execute(action.target, action.value, action.data, action.salt)
    ).to.be.revertedWith(`AccessControl: account ${randomAddress.address.toLowerCase()} is missing role ${action.id}`);

    await expect(re.connect(authorizer).grantRole(action.id, randomAddress.address))
      .to.emit(re, "RoleGranted")
      .withArgs(action.id, randomAddress.address, authorizer.address);

    await expect(re.connect(randomAddress).execute(action.target, action.value, action.data, action.salt))
      .to.emit(callReceiver, "Role1FunctionExecuted")
      .withArgs(keccak256("testing"), 280);
  });
});

function createAction(target, value, data, salt) {
  const id = keccak256(
    hre.web3.eth.abi.encodeParameters(["address", "uint256", "bytes", "bytes32"], [target, value, data, salt])
  );

  return { id, target, value, data, salt };
}
