const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { accessControlMessage, createCall, createBatch, simpleContractFixture } = require("./fixtures");
const { PROPOSER_ROLE, AUTHORIZER_ROLE, DEFAULT_ADMIN_ROLE } = require("./constants");

const keccak256 = hre.web3.utils.keccak256;

describe("Payable calls", () => {
  it("forwards eth to the target contract on simple calls", async () => {
    const { owner, proposer, authorizer, signers, restrictedExecutor, callReceiver, receiverEncode } =
      await loadFixture(simpleContractFixture);
    const [randomAddress] = signers;

    const ethAmount = hre.ethers.utils.parseEther("2.5");
    const call = createCall(callReceiver.address, receiverEncode("payableFunction", []), ethAmount);

    await restrictedExecutor
      .connect(proposer)
      .create(call.target, call.value, call.data, call.salt, hre.ethers.constants.MaxUint256);
    await restrictedExecutor.connect(authorizer).grantRole(call.id, randomAddress.address);

    const tx = restrictedExecutor
      .connect(randomAddress)
      .execute(call.target, call.value, call.data, call.salt, { value: ethAmount });

    await expect(tx).to.emit(callReceiver, "PayableExecuted").withArgs(ethAmount);
    await expect(tx).to.changeEtherBalance(randomAddress, ethAmount.mul(-1));
    expect(await callReceiver.provider.getBalance(callReceiver.address)).to.equal(ethAmount);
  });

  it("forwards eth to the target contract on batch calls", async () => {
    const { owner, proposer, authorizer, signers, restrictedExecutor, callReceiver, receiverEncode } =
      await loadFixture(simpleContractFixture);
    const [randomAddress] = signers;

    const ethAmount = hre.ethers.utils.parseEther("5.2");
    const batch = createBatch([callReceiver.address], [receiverEncode("payableFunction", [])], [ethAmount]);

    await restrictedExecutor
      .connect(proposer)
      .createBatch(batch.targets, batch.values, batch.payloads, batch.salt, hre.ethers.constants.MaxUint256);
    await restrictedExecutor.connect(authorizer).grantRole(batch.id, randomAddress.address);

    const tx = restrictedExecutor
      .connect(randomAddress)
      .executeBatch(batch.targets, batch.values, batch.payloads, batch.salt, { value: ethAmount });

    await expect(tx).to.emit(callReceiver, "PayableExecuted").withArgs(ethAmount);
    await expect(tx).to.changeEtherBalance(randomAddress, ethAmount.mul(-1));
    expect(await callReceiver.provider.getBalance(callReceiver.address)).to.equal(ethAmount);
  });

  it("reverts if eth is not enough for target contract", async () => {
    const { owner, proposer, authorizer, signers, restrictedExecutor, callReceiver, receiverEncode } =
      await loadFixture(simpleContractFixture);
    const [randomAddress] = signers;

    const ethAmount = hre.ethers.utils.parseEther("0.3");
    const batch = createBatch([callReceiver.address], [receiverEncode("payableFunction", [])], [ethAmount]);

    await restrictedExecutor
      .connect(proposer)
      .createBatch(batch.targets, batch.values, batch.payloads, batch.salt, hre.ethers.constants.MaxUint256);
    await restrictedExecutor.connect(authorizer).grantRole(batch.id, randomAddress.address);

    await expect(
      restrictedExecutor
        .connect(randomAddress)
        .executeBatch(batch.targets, batch.values, batch.payloads, batch.salt, { value: ethAmount })
    ).to.be.revertedWith("RestrictedExecutor: underlying transaction reverted");
  });
});
