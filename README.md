# Restricted Executor

This is a Solidity smart contract that enables authorized actors to call other contracts with specific parameters.

## Functionality

The main use case for the Restricted Executor contract is to allow more granularity on contracts with wide access controls, like an `Ownable` contract or an `AccessControl` contract with an admin role.

It supports four main roles:

- PROPOSER_ROLE: can create new operations
- CANCELLER_ROLE: can cancel existing operations
- AUTHORIZER_ROLE: can authorize operation execution
- UPGRADER_ROLE: can upgrade the contract

The contract can create new operations containing a single call or a batch of calls. Each call specifies a target contract, an ether amount to send along with the call, and an encoded payload for the target contract (an encoded function call). A salt is used to ensure unicity of the operation id.

The operation id is then used as a role administered by the AUTHORIZER_ROLE to authorize addresses execution permission.

## License

This contract is licensed under the MIT license.

## Installation

You can clone this repository and install the dependencies using NPM:

```
npm install
```

## Testing

To run the tests, you need to have hardhat installed globally:

```sh
npx hardhat test
```

For gas reporting:

```sh
REPORT_GAS=true npx hardhat test

```

For test coverage reporting:

```sh
npx hardhat coverage
```
