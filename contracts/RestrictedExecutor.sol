// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title Restricted Executor
 * @author Ensuro Dev Team <dev@ensuro.co>
 * @notice This contract allows authorized actors to call other contracts with specific parameters.
 *
 * The main use case is to handle more granularity on contracts with wide access controls, like an
 * Ownable contract or an AccessControl contract with an admin role.
 *
 * Mostly inspired on [OpenZeppelin's TimeLockController](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/governance/TimelockController.sol)
 */
contract RestrictedExecutor is Initializable, AccessControlUpgradeable, UUPSUpgradeable {
  /**
   * @notice Can create new operations
   */
  bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");

  /**
   * @notice Can cancel existing operations
   */
  bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");

  /**
   * @notice Can authorize operation execution
   */
  bytes32 public constant AUTHORIZER_ROLE = keccak256("AUTHORIZER_ROLE");

  /**
   * @notice Can upgrade this contract
   */
  bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

  /**
   * @dev operationId -> bool mapping
   */
  mapping(bytes32 => uint256) private _operations;

  event CallCreated(
    bytes32 indexed id,
    uint256 indexed index,
    address target,
    uint256 value,
    bytes data,
    bytes32 salt,
    uint256 maxExecutions
  );

  event CallExecuted(
    bytes32 indexed id,
    uint256 indexed index,
    address target,
    uint256 value,
    bytes data
  );

  event Cancelled(bytes32 indexed id);

  function initialize(address[] memory authorizers, address[] memory proposers) public initializer {
    __AccessControl_init();
    __UUPSUpgradeable_init();
    __RestrictedExecutor_init_unchained(authorizers, proposers);
  }

  /**
   * @dev Contract might receive/hold ETH as part of the maintenance process.
   */
  receive() external payable {}

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
    bytes32 salt,
    uint256 maxExecutions
  ) public virtual onlyRole(PROPOSER_ROLE) {
    require(maxExecutions > 0, "RestrictedExecutor: invalid maxExecutions value");

    bytes32 id = hashCall(target, value, data, salt);
    _operations[id] = maxExecutions;
    _setRoleAdmin(id, AUTHORIZER_ROLE);
    emit CallCreated(id, 0, target, value, data, salt, maxExecutions);
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
    bytes32 salt,
    uint256 maxExecutions
  ) public virtual onlyRole(PROPOSER_ROLE) {
    require(targets.length == values.length, "RestrictedExecutor: length mistmatch");
    require(targets.length == payloads.length, "RestrictedExecutor: length mistmatch");
    require(maxExecutions > 0, "RestrictedExecutor: invalid maxExecutions value");

    bytes32 id = hashCallBatch(targets, values, payloads, salt);
    _operations[id] = maxExecutions;
    _setRoleAdmin(id, AUTHORIZER_ROLE);

    for (uint256 i = 0; i < targets.length; ++i) {
      emit CallCreated(id, i, targets[i], values[i], payloads[i], salt, maxExecutions);
    }
  }

  function cancel(bytes32 id) public virtual onlyRole(CANCELLER_ROLE) {
    require(_operations[id] > 0, "RestrictedExecutor: unknown operation");
    delete _operations[id];

    emit Cancelled(id);
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
   * @dev Executes an operation with a single call. Check hashCall for parameter details.
   *
   * Requirements:
   *   - Operation was created
   *   - msg.sender has been granted permissions on the operation
   */
  function execute(
    address target,
    uint256 value,
    bytes calldata data,
    bytes32 salt
  ) public payable virtual {
    // checks
    bytes32 id = hashCall(target, value, data, salt);
    require(_operations[id] > 0, "RestrictedExecutor: unknown operation");
    _checkRoleOrOpenRole(id);

    //effects
    if (_operations[id] != type(uint256).max) _operations[id] -= 1;

    // interactions
    _execute(target, value, data);
    emit CallExecuted(id, 0, target, value, data);
  }

  /**
   *
   * @dev Executes an operation with a call batch. Check hashCallBatch for parameter details.
   *
   * Requirements:
   *   - Operation was created
   *   - msg.sender has been granted permissions on the operation
   */
  function executeBatch(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata payloads,
    bytes32 salt
  ) public payable virtual {
    // checks
    require(targets.length == values.length, "RestrictedExecutor: batch length mismatch");
    require(targets.length == payloads.length, "RestrictedExecutor: batch length mismatch");
    bytes32 id = hashCallBatch(targets, values, payloads, salt);
    require(_operations[id] > 0, "RestrictedExecutor: unknown operation");
    _checkRoleOrOpenRole(id);

    // effects
    if (_operations[id] != type(uint256).max) _operations[id] -= 1;

    // interactions
    for (uint256 i = 0; i < targets.length; ++i) {
      _execute(targets[i], values[i], payloads[i]);
      emit CallExecuted(id, i, targets[i], values[i], payloads[i]);
    }
  }

  /**
   * @param id the operationId to query
   * @return remaining the number of executions remaining
   */
  function getRemainingExecutions(bytes32 id) public view returns (uint256 remaining) {
    return _operations[id];
  }
}
