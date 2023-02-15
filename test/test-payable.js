const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const { createCall, createBatch, simpleContractFixture } = require("./fixtures");

describe("Payable calls", () => {
  it("forwards eth to the target contract on simple calls", async () => {
    const { proposer, authorizer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
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
    const { proposer, authorizer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
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
    const { proposer, authorizer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
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

  it("restricted executor can pay for calls itself", async () => {
    const { proposer, authorizer, signers, restrictedExecutor, callReceiver, receiverEncode } = await loadFixture(
      simpleContractFixture
    );
    const [randomAddress] = signers;

    await randomAddress.sendTransaction({ to: restrictedExecutor.address, value: hre.ethers.utils.parseEther("1000") });
    expect(await restrictedExecutor.provider.getBalance(restrictedExecutor.address)).to.equal(
      hre.ethers.utils.parseEther("1000")
    );

    const ethAmount = hre.ethers.utils.parseEther("10.9");
    const call = createCall(callReceiver.address, receiverEncode("payableFunction", []), ethAmount);

    await restrictedExecutor
      .connect(proposer)
      .create(call.target, call.value, call.data, call.salt, hre.ethers.constants.MaxUint256);
    await restrictedExecutor.connect(authorizer).grantRole(call.id, randomAddress.address);

    // Tx is sent without ETH
    const tx = restrictedExecutor.connect(randomAddress).execute(call.target, call.value, call.data, call.salt);

    await expect(tx).to.emit(callReceiver, "PayableExecuted").withArgs(ethAmount);
    await expect(tx).to.changeEtherBalance(restrictedExecutor.address, ethAmount.mul(-1));
    expect(await callReceiver.provider.getBalance(callReceiver.address)).to.equal(ethAmount);
  });
});
