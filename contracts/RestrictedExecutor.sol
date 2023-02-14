// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "hardhat/console.sol";

contract RestrictedExecutor is Initializable, AccessControlUpgradeable, UUPSUpgradeable {
  /**
   * @notice Can authorize Calls
   */
  bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");

  bytes32 public constant AUTHORIZER_ROLE = keccak256("AUTHORIZER_ROLE");

  bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

  /**
   * @dev callId -> bool mapping
   */
  mapping(bytes32 => bool) private _operations;

  event CallCreated(
    bytes32 indexed id,
    uint256 index,
    address target,
    uint256 value,
    bytes data,
    bytes32 salt
  );

  event CallExecuted(
    bytes32 indexed id,
    uint256 index,
    address target,
    uint256 value,
    bytes data,
    bytes32 salt
  );

  function initialize(address[] memory authorizers, address[] memory proposers) public initializer {
    __AccessControl_init();
    __UUPSUpgradeable_init();
    __RestrictedExecutor_init_unchained(authorizers, proposers);
  }

  // solhint-disable-next-line func-name-mixedcase
  function __RestrictedExecutor_init_unchained(
    address[] memory authorizers,
    address[] memory proposers
  ) internal onlyInitializing {
    for (uint256 i = 0; i < authorizers.length; ++i) {
      _setupRole(AUTHORIZER_ROLE, authorizers[i]);
    }

    for (uint256 i = 0; i < proposers.length; ++i) {
      _setupRole(PROPOSER_ROLE, proposers[i]);
    }

    _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
  }

  /**
   * @dev Check that _msgSender() has role. In addition to checking the sender's role, `address(0)`'s
   * role is also considered. Granting a role to `address(0)` is equivalent to enabling this role
   * for everyone.
   *
   * Inspired on [OpenZeppelin's TimeLockController `onlyRoleOrOpenRole` modifier](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/governance/TimelockController.sol)
   *
   */
  function _checkRoleOrOpenRole(bytes32 role) internal view {
    if (!hasRole(role, address(0))) {
      _checkRole(role, _msgSender());
    }
  }

  function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

  /**
   * @dev Hashes a single call to create an operation id
   * @param target the target contract
   * @param value the ether amount to send along with the call
   * @param data the encoded payload for the target contract (an encoded function call)
   * @param salt a salt to ensure call id unicity, usually just zero
   * @return hash the call hash / operation id
   */
  function hashCall(
    address target,
    uint256 value,
    bytes calldata data,
    bytes32 salt
  ) public pure virtual returns (bytes32 hash) {
    return keccak256(abi.encode(target, value, data, salt));
  }

  /**
   * @dev Hashes a batch of calls to create an operation id
   * @param targets the target contracts
   * @param values the ether amounts to send along with the contract calls
   * @param payloads the encoded payloads for the target contracts (encoded function calls)
   * @param salt a salt to ensure operation id unicity, usually just zero
   * @return hash the call batch hash / operation id
   */
  function hashCallBatch(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata payloads,
    bytes32 salt
  ) public pure virtual returns (bytes32 hash) {
    return keccak256(abi.encode(targets, values, payloads, salt));
  }

  /**
   *
   * @dev Creates a new operation containing a single call. Check hashCall for parameter details.
   *
   * Requirements:
   *   - onlyRole(PROPOSER_ROLE)
   *
   * Events:
   *   - CallCreated with the operation id and call details
   *   - RoleAdminChanged granting AUTHORIZER_ROLE admin on the new operation
   */
  function create(
    address target,
    uint256 value,
    bytes calldata data,
    bytes32 salt
  ) public virtual onlyRole(PROPOSER_ROLE) {
    bytes32 id = hashCall(target, value, data, salt);
    _operations[id] = true;
    _setRoleAdmin(id, AUTHORIZER_ROLE);
    emit CallCreated(id, 0, target, value, data, salt);
  }

  /**
   *
   * @dev Creates an operation containing a batch of calls. Check hashCallBatch for parameter details.
   *
   * Requirements:
   *   - onlyRole(PROPOSER_ROLE)
   *
   * Events:
   *   - CallCreated for each call in the batch, all with the same call id
   *   - RoleAdminChanged granting AUTHORIZER_ROLE admin on the new call
   */
  function createBatch(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata payloads,
    bytes32 salt
  ) public virtual onlyRole(PROPOSER_ROLE) {
    require(targets.length == values.length, "RestrictedExecutor: length mistmatch");
    require(targets.length == payloads.length, "RestrictedExecutor: length mistmatch");

    bytes32 id = hashCallBatch(targets, values, payloads, salt);
    _operations[id] = true;
    _setRoleAdmin(id, AUTHORIZER_ROLE);

    for (uint256 i = 0; i < targets.length; ++i) {
      emit CallCreated(id, i, targets[i], values[i], payloads[i], salt);
    }
  }

  /**
   * @dev Execute a single call and check for success
   */
  function _execute(address target, uint256 value, bytes calldata data) internal virtual {
    (bool success, ) = target.call{value: value}(data);
    require(success, "RestrictedExecutor: underlying transaction reverted");
  }

  /**
   *
   * @dev Executes a call. Check hashCall for parameter details.
   *
   * Requirements:
   *   - Call was created
   *   - msg.sender has been granted permissions on the call
   */
  function execute(
    address target,
    uint256 value,
    bytes calldata data,
    bytes32 salt
  ) public virtual {
    bytes32 id = hashCall(target, value, data, salt);
    require(_operations[id], "RestrictedExecutor: unknown operation");
    _checkRoleOrOpenRole(id);
    _execute(target, value, data);
  }

  /**
   *
   * @dev Executes a call batch. Check hashCallBatch for parameter details.
   *
   * Requirements:
   *   - Call batch was created
   *   - msg.sender has been granted permissions on the call
   */
  function executeBatch(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata payloads,
    bytes32 salt
  ) public virtual {
    require(targets.length == values.length, "RestrictedExecutor: batch length mismatch");
    require(targets.length == payloads.length, "RestrictedExecutor: batch length mismatch");
    bytes32 id = hashCallBatch(targets, values, payloads, salt);
    require(_operations[id], "RestrictedExecutor: unkwnown call");
    _checkRoleOrOpenRole(id);

    for (uint256 i = 0; i < targets.length; ++i) {
      _execute(targets[i], values[i], payloads[i]);
    }

    // TODO: reentrancy check/guard ??
  }
}
