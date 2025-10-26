// Sources flattened with hardhat v3.0.9 https://hardhat.org

// SPDX-License-Identifier: MIT

// File npm/@chainlink/contracts@1.5.0/src/v0.8/shared/interfaces/AggregatorV3Interface.sol

// Original license: SPDX_License_Identifier: MIT
pragma solidity ^0.8.0;

// solhint-disable-next-line interface-starts-with-i
interface AggregatorV3Interface {
  function decimals() external view returns (uint8);

  function description() external view returns (string memory);

  function version() external view returns (uint256);

  function getRoundData(
    uint80 _roundId
  ) external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

  function latestRoundData()
    external
    view
    returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}


// File npm/@openzeppelin/contracts@5.4.0/access/IAccessControl.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (access/IAccessControl.sol)

pragma solidity >=0.8.4;

/**
 * @dev External interface of AccessControl declared to support ERC-165 detection.
 */
interface IAccessControl {
    /**
     * @dev The `account` is missing a role.
     */
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /**
     * @dev The caller of a function is not the expected one.
     *
     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.
     */
    error AccessControlBadConfirmation();

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted to signal this.
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call. This account bears the admin role (for the granted role).
     * Expected in cases where the role was granted using the internal {AccessControl-_grantRole}.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) external view returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     */
    function renounceRole(bytes32 role, address callerConfirmation) external;
}


// File npm/@openzeppelin/contracts@5.4.0/utils/Context.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}


// File npm/@openzeppelin/contracts@5.4.0/utils/introspection/IERC165.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (utils/introspection/IERC165.sol)

pragma solidity >=0.4.16;

/**
 * @dev Interface of the ERC-165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[ERC].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}


// File npm/@openzeppelin/contracts@5.4.0/utils/introspection/ERC165.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (utils/introspection/ERC165.sol)

pragma solidity ^0.8.20;

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC-165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 */
abstract contract ERC165 is IERC165 {
    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}


// File npm/@openzeppelin/contracts@5.4.0/access/AccessControl.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (access/AccessControl.sol)

pragma solidity ^0.8.20;



/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version that doesn't allow enumerating role
 * members except through off-chain means by accessing the contract event logs. Some
 * applications may benefit from on-chain enumerability, for those cases see
 * {AccessControlEnumerable}.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```solidity
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```solidity
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it. We recommend using {AccessControlDefaultAdminRules}
 * to enforce additional security measures for this role.
 */
abstract contract AccessControl is Context, IAccessControl, ERC165 {
    struct RoleData {
        mapping(address account => bool) hasRole;
        bytes32 adminRole;
    }

    mapping(bytes32 role => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with an {AccessControlUnauthorizedAccount} error including the required role.
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
        return _roles[role].hasRole[account];
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`
     * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(bytes32 role, address callerConfirmation) public virtual {
        if (callerConfirmation != _msgSender()) {
            revert AccessControlBadConfirmation();
        }

        _revokeRole(role, callerConfirmation);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(bytes32 role, address account) internal virtual returns (bool) {
        if (!hasRole(role, account)) {
            _roles[role].hasRole[account] = true;
            emit RoleGranted(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` from `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(bytes32 role, address account) internal virtual returns (bool) {
        if (hasRole(role, account)) {
            _roles[role].hasRole[account] = false;
            emit RoleRevoked(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }
}


// File npm/@openzeppelin/contracts@5.4.0/interfaces/IERC165.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/IERC165.sol)

pragma solidity >=0.4.16;


// File npm/@openzeppelin/contracts@5.4.0/token/ERC20/IERC20.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (token/ERC20/IERC20.sol)

pragma solidity >=0.4.16;

/**
 * @dev Interface of the ERC-20 standard as defined in the ERC.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}


// File npm/@openzeppelin/contracts@5.4.0/interfaces/IERC20.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/IERC20.sol)

pragma solidity >=0.4.16;


// File npm/@openzeppelin/contracts@5.4.0/interfaces/IERC1363.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/IERC1363.sol)

pragma solidity >=0.6.2;


/**
 * @title IERC1363
 * @dev Interface of the ERC-1363 standard as defined in the https://eips.ethereum.org/EIPS/eip-1363[ERC-1363].
 *
 * Defines an extension interface for ERC-20 tokens that supports executing code on a recipient contract
 * after `transfer` or `transferFrom`, or code on a spender contract after `approve`, in a single transaction.
 */
interface IERC1363 is IERC20, IERC165 {
    /*
     * Note: the ERC-165 identifier for this interface is 0xb0202a11.
     * 0xb0202a11 ===
     *   bytes4(keccak256('transferAndCall(address,uint256)')) ^
     *   bytes4(keccak256('transferAndCall(address,uint256,bytes)')) ^
     *   bytes4(keccak256('transferFromAndCall(address,address,uint256)')) ^
     *   bytes4(keccak256('transferFromAndCall(address,address,uint256,bytes)')) ^
     *   bytes4(keccak256('approveAndCall(address,uint256)')) ^
     *   bytes4(keccak256('approveAndCall(address,uint256,bytes)'))
     */

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferAndCall(address to, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @param data Additional data with no specified format, sent in call to `to`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferAndCall(address to, uint256 value, bytes calldata data) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferFromAndCall(address from, address to, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @param data Additional data with no specified format, sent in call to `to`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferFromAndCall(address from, address to, uint256 value, bytes calldata data) external returns (bool);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens and then calls {IERC1363Spender-onApprovalReceived} on `spender`.
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function approveAndCall(address spender, uint256 value) external returns (bool);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens and then calls {IERC1363Spender-onApprovalReceived} on `spender`.
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     * @param data Additional data with no specified format, sent in call to `spender`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function approveAndCall(address spender, uint256 value, bytes calldata data) external returns (bool);
}


// File npm/@openzeppelin/contracts@5.4.0/token/ERC20/utils/SafeERC20.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.3.0) (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.20;


/**
 * @title SafeERC20
 * @dev Wrappers around ERC-20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    /**
     * @dev An operation with an ERC-20 token failed.
     */
    error SafeERC20FailedOperation(address token);

    /**
     * @dev Indicates a failed `decreaseAllowance` request.
     */
    error SafeERC20FailedDecreaseAllowance(address spender, uint256 currentAllowance, uint256 requestedDecrease);

    /**
     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    /**
     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the
     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.
     */
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    /**
     * @dev Variant of {safeTransfer} that returns a bool instead of reverting if the operation is not successful.
     */
    function trySafeTransfer(IERC20 token, address to, uint256 value) internal returns (bool) {
        return _callOptionalReturnBool(token, abi.encodeCall(token.transfer, (to, value)));
    }

    /**
     * @dev Variant of {safeTransferFrom} that returns a bool instead of reverting if the operation is not successful.
     */
    function trySafeTransferFrom(IERC20 token, address from, address to, uint256 value) internal returns (bool) {
        return _callOptionalReturnBool(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    /**
     * @dev Increase the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     *
     * IMPORTANT: If the token implements ERC-7674 (ERC-20 with temporary allowance), and if the "client"
     * smart contract uses ERC-7674 to set temporary allowances, then the "client" smart contract should avoid using
     * this function. Performing a {safeIncreaseAllowance} or {safeDecreaseAllowance} operation on a token contract
     * that has a non-zero temporary allowance (for that particular owner-spender) will result in unexpected behavior.
     */
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        forceApprove(token, spender, oldAllowance + value);
    }

    /**
     * @dev Decrease the calling contract's allowance toward `spender` by `requestedDecrease`. If `token` returns no
     * value, non-reverting calls are assumed to be successful.
     *
     * IMPORTANT: If the token implements ERC-7674 (ERC-20 with temporary allowance), and if the "client"
     * smart contract uses ERC-7674 to set temporary allowances, then the "client" smart contract should avoid using
     * this function. Performing a {safeIncreaseAllowance} or {safeDecreaseAllowance} operation on a token contract
     * that has a non-zero temporary allowance (for that particular owner-spender) will result in unexpected behavior.
     */
    function safeDecreaseAllowance(IERC20 token, address spender, uint256 requestedDecrease) internal {
        unchecked {
            uint256 currentAllowance = token.allowance(address(this), spender);
            if (currentAllowance < requestedDecrease) {
                revert SafeERC20FailedDecreaseAllowance(spender, currentAllowance, requestedDecrease);
            }
            forceApprove(token, spender, currentAllowance - requestedDecrease);
        }
    }

    /**
     * @dev Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful. Meant to be used with tokens that require the approval
     * to be set to zero before setting it to a non-zero value, such as USDT.
     *
     * NOTE: If the token implements ERC-7674, this function will not modify any temporary allowance. This function
     * only sets the "standard" allowance. Any temporary allowance will remain active, in addition to the value being
     * set here.
     */
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory approvalCall = abi.encodeCall(token.approve, (spender, value));

        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(token, abi.encodeCall(token.approve, (spender, 0)));
            _callOptionalReturn(token, approvalCall);
        }
    }

    /**
     * @dev Performs an {ERC1363} transferAndCall, with a fallback to the simple {ERC20} transfer if the target has no
     * code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * Reverts if the returned value is other than `true`.
     */
    function transferAndCallRelaxed(IERC1363 token, address to, uint256 value, bytes memory data) internal {
        if (to.code.length == 0) {
            safeTransfer(token, to, value);
        } else if (!token.transferAndCall(to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Performs an {ERC1363} transferFromAndCall, with a fallback to the simple {ERC20} transferFrom if the target
     * has no code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * Reverts if the returned value is other than `true`.
     */
    function transferFromAndCallRelaxed(
        IERC1363 token,
        address from,
        address to,
        uint256 value,
        bytes memory data
    ) internal {
        if (to.code.length == 0) {
            safeTransferFrom(token, from, to, value);
        } else if (!token.transferFromAndCall(from, to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Performs an {ERC1363} approveAndCall, with a fallback to the simple {ERC20} approve if the target has no
     * code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * NOTE: When the recipient address (`to`) has no code (i.e. is an EOA), this function behaves as {forceApprove}.
     * Opposedly, when the recipient address (`to`) has code, this function only attempts to call {ERC1363-approveAndCall}
     * once without retrying, and relies on the returned value to be true.
     *
     * Reverts if the returned value is other than `true`.
     */
    function approveAndCallRelaxed(IERC1363 token, address to, uint256 value, bytes memory data) internal {
        if (to.code.length == 0) {
            forceApprove(token, to, value);
        } else if (!token.approveAndCall(to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturnBool} that reverts if call fails to meet the requirements.
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        uint256 returnSize;
        uint256 returnValue;
        assembly ("memory-safe") {
            let success := call(gas(), token, 0, add(data, 0x20), mload(data), 0, 0x20)
            // bubble errors
            if iszero(success) {
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
            returnSize := returndatasize()
            returnValue := mload(0)
        }

        if (returnSize == 0 ? address(token).code.length == 0 : returnValue != 1) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturn} that silently catches all reverts and returns a bool instead.
     */
    function _callOptionalReturnBool(IERC20 token, bytes memory data) private returns (bool) {
        bool success;
        uint256 returnSize;
        uint256 returnValue;
        assembly ("memory-safe") {
            success := call(gas(), token, 0, add(data, 0x20), mload(data), 0, 0x20)
            returnSize := returndatasize()
            returnValue := mload(0)
        }
        return success && (returnSize == 0 ? address(token).code.length > 0 : returnValue == 1);
    }
}


// File npm/@openzeppelin/contracts@5.4.0/utils/ReentrancyGuard.sol

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/ReentrancyGuard.sol)

pragma solidity ^0.8.20;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If EIP-1153 (transient storage) is available on the chain you're deploying at,
 * consider using {ReentrancyGuardTransient} instead.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    uint256 private _status;

    /**
     * @dev Unauthorized reentrant call.
     */
    error ReentrancyGuardReentrantCall();

    constructor() {
        _status = NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        if (_status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }

        // Any calls to nonReentrant after this point will fail
        _status = ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == ENTERED;
    }
}


// File contracts/KipuBankV2.sol

// Original license: SPDX_License_Identifier: MIT
pragma solidity ^0.8.26;




/**
 * @title KipuBankV2
 * @author Jonathan Chacon
 * @notice Improved multi-token vault with Chainlink price feeds, role-based access control,
 *         and per-token withdrawal limits denominated in USD (18 decimals).
 * @dev Educational/refactor exercise (TP3). NOT for production use.
 *      - Uses OpenZeppelin AccessControl and ReentrancyGuard.
 *      - Stores caps and accounting in USD (18 decimals) using Chainlink feeds (usually 8 decimals).
 *      - Uses SafeERC20 for ERC-20 transfers.
 */
contract KipuBankV2 is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /*////////////////////////////////////////////////////////////
                          ROLES & CONSTANTS
    ////////////////////////////////////////////////////////////*/

    /// @notice Role allowed to configure price feeds and withdrawal limits.
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Chainlink price feeds usually return with 8 decimals.
    uint8 public constant CHAINLINK_PRICE_DECIMALS = 8;

    /*////////////////////////////////////////////////////////////
                            IMMUTABLES
    ////////////////////////////////////////////////////////////*/

    /// @notice Price feed for native ETH/USD (immutable after construction).
    AggregatorV3Interface public immutable i_ethPriceFeed;

    /*////////////////////////////////////////////////////////////
                            STATE
    ////////////////////////////////////////////////////////////*/

    /// @notice Global bank cap expressed in USD with 18 decimals.
    uint256 public s_bankCapUSD;

    /// @notice Global total deposited expressed in USD with 18 decimals.
    uint256 public s_totalDepositedUSD;

    /// @notice Nested mapping: user => token => token balance (in token native units).
    mapping(address => mapping(address => uint256)) private s_balances;

    /// @notice Mapping token => Chainlink price feed.
    mapping(address => AggregatorV3Interface) private s_tokenPriceFeeds;

    /// @notice Mapping token => per-transaction withdrawal limit in USD (18 decimals).
    mapping(address => uint256) public s_tokenWithdrawalLimitsUSD;

    /// @notice Counters
    uint256 public s_totalDepositsCount;
    uint256 public s_totalWithdrawalsCount;

    /*////////////////////////////////////////////////////////////
                            EVENTS
    ////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a token's price feed is updated.
    /// @param token Token address.
    /// @param feed AggregatorV3Interface feed address.
    event TokenPriceFeedUpdated(address indexed token, address indexed feed);

    /// @notice Emitted when a token's per-transaction withdrawal limit is updated.
    /// @param token Token address.
    /// @param newLimitUSD New limit in USD (18 decimals).
    event WithdrawalLimitUpdated(address indexed token, uint256 newLimitUSD);

    /// @notice Emitted when a deposit occurs.
    /// @param sender Account depositing.
    /// @param token Token address (address(0) for ETH).
    /// @param amount Amount deposited in native token units.
    /// @param valueUSD Equivalent value in USD (18 decimals).
    event Deposit(
        address indexed sender,
        address indexed token,
        uint256 amount,
        uint256 valueUSD
    );

    /// @notice Emitted when a withdrawal occurs.
    /// @param sender Account withdrawing.
    /// @param token Token address (address(0) for ETH).
    /// @param amount Amount withdrawn in native token units.
    /// @param valueUSD Equivalent value in USD (18 decimals).
    event Withdraw(
        address indexed sender,
        address indexed token,
        uint256 amount,
        uint256 valueUSD
    );

    /*////////////////////////////////////////////////////////////
                            ERRORS
    ////////////////////////////////////////////////////////////*/

    error InvalidZeroDeposit();
    error InvalidZeroWithdrawal();
    error DepositCapExceeded(uint256 amountUSD, uint256 remainingUSD);
    error PriceFeedNotSet(address token);
    error PriceFeedInvalid();
    error InsufficientBalance(uint256 balance, uint256 requested);
    error WithdrawalLimitNotSet(address token);
    error WithdrawalLimitExceeded(uint256 amountUSD, uint256 limitUSD);
    error TransferFailed(bytes err);
    error ReentrancyDetected();
    error InvalidTokenAddress();
    error InvalidDepositAmount();

    /*////////////////////////////////////////////////////////////
                            MODIFIERS
    ////////////////////////////////////////////////////////////*/

    modifier onlyOperator() {
        require(hasRole(OPERATOR_ROLE, msg.sender), "NOT_OPERATOR");
        _;
    }

    /*////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    ////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize KipuBankV2.
     * @param _initialCapUSD Initial global cap in USD (18 decimals).
     * @param _ethPriceFeed Address of Chainlink ETH/USD price feed.
     * @param _admin Address that will receive DEFAULT_ADMIN_ROLE and OPERATOR_ROLE.
     * @dev The admin receives both DEFAULT_ADMIN_ROLE and OPERATOR_ROLE to bootstrap configuration.
     */
    constructor(uint256 _initialCapUSD, address _ethPriceFeed, address _admin) {
        i_ethPriceFeed = AggregatorV3Interface(_ethPriceFeed);
        s_bankCapUSD = _initialCapUSD;
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
    }

    /*////////////////////////////////////////////////////////////
                          OPERATOR / ADMIN FUNCTIONS
    ////////////////////////////////////////////////////////////*/

    /**
     * @notice Set or update a token's Chainlink price feed (address(0) is reserved for ETH).
     * @param _token Token address to configure (address(0) is reserved).
     * @param _feed AggregatorV3Interface address for the token price.
     * @dev Only callable by OPERATOR_ROLE. Reverts if `_token` is address(0).
     */
    function setTokenPriceFeed(address _token, address _feed) external onlyOperator {
        if (_token == address(0)) revert InvalidTokenAddress();
        s_tokenPriceFeeds[_token] = AggregatorV3Interface(_feed);
        emit TokenPriceFeedUpdated(_token, _feed);
    }

    /**
     * @notice Set per-token withdrawal limit (in USD, 18 decimals). Use address(0) for ETH.
     * @param _token Token address to configure (address(0) for ETH).
     * @param _limitUSD New limit expressed in USD with 18 decimals.
     * @dev Only callable by OPERATOR_ROLE.
     */
    function setWithdrawalLimitUSD(address _token, uint256 _limitUSD) external onlyOperator {
        s_tokenWithdrawalLimitsUSD[_token] = _limitUSD;
        emit WithdrawalLimitUpdated(_token, _limitUSD);
    }

    /**
     * @notice Update global bank cap in USD (18 decimals).
     * @param _newCapUSD New global cap in USD (18 decimals).
     * @dev Only callable by DEFAULT_ADMIN_ROLE.
     */
    function setBankCapUSD(uint256 _newCapUSD) external onlyRole(DEFAULT_ADMIN_ROLE) {
        s_bankCapUSD = _newCapUSD;
    }

    /*////////////////////////////////////////////////////////////
                                DEPOSITS
    ////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit ETH (token == address(0)) or ERC20 tokens.
     * @param _token Token address to deposit (address(0) for ETH).
     * @param _amount Amount to deposit (for ETH must equal msg.value).
     * @dev Performs: 1) pull tokens or accept ETH, 2) convert to USD, 3) validate global cap, 4) update accounting, 5) emit event.
     *      Uses OpenZeppelin's ReentrancyGuard `nonReentrant`.
     */
    function deposit(address _token, uint256 _amount) external payable nonReentrant {
        if (_amount == 0) revert InvalidZeroDeposit();

        if (_token == address(0)) {
            // ETH deposit
            if (msg.value != _amount) revert InvalidDepositAmount();
        } else {
            // ERC20 deposit: pull tokens using safe transferFrom
            IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        }

        // Convert to USD and validate cap
        uint256 valueUSD = _toUsd18(_token, _amount);
        _validateCapUSD(valueUSD);

        // Effects
        s_balances[msg.sender][_token] += _amount;
        s_totalDepositedUSD += valueUSD;
        ++s_totalDepositsCount;

        emit Deposit(msg.sender, _token, _amount, valueUSD);
    }

    /*////////////////////////////////////////////////////////////
                                WITHDRAWALS
    ////////////////////////////////////////////////////////////*/

    /**
     * @notice Withdraw a token amount if allowed by balance and per-token USD limit.
     * @param _token Token address to withdraw (address(0) for ETH).
     * @param _amount Amount to withdraw (token native units).
     * @dev Performs Checks → Effects → Interaction and uses `nonReentrant`.
     */
    function withdraw(address _token, uint256 _amount) external nonReentrant {
        if (_amount == 0) revert InvalidZeroWithdrawal();

        uint256 _userBalance = s_balances[msg.sender][_token];
        if (_amount > _userBalance) revert InsufficientBalance(_userBalance, _amount);

        // Check withdrawal limit in USD
        uint256 _amountUSD = _toUsd18(_token, _amount);
        uint256 _limitUSD = s_tokenWithdrawalLimitsUSD[_token];
        if (_limitUSD == 0) revert WithdrawalLimitNotSet(_token);
        if (_amountUSD > _limitUSD) revert WithdrawalLimitExceeded(_amountUSD, _limitUSD);

        // Effects
        unchecked {
            s_balances[msg.sender][_token] = _userBalance - _amount;
        }
        s_totalDepositedUSD -= _amountUSD;
        ++s_totalWithdrawalsCount;

        // Interaction (transfer at the end)
        if (_token == address(0)) {
            _safeTransferETH(msg.sender, _amount);
        } else {
            IERC20(_token).safeTransfer(msg.sender, _amount);
        }

        emit Withdraw(msg.sender, _token, _amount, _amountUSD);
    }

    /*////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
    ////////////////////////////////////////////////////////////*/

    /**
     * @notice Safely transfer ETH and bubble revert reason.
     * @param _to Recipient address.
     * @param _amount Amount of wei to send.
     * @dev Uses low-level `.call` and reverts with the returned data on failure.
     */
    function _safeTransferETH(address _to, uint256 _amount) internal {
        (bool success, bytes memory data) = _to.call{value: _amount}("");
        if (!success) revert TransferFailed(data);
    }

    /**
     * @notice Convert a token amount to USD with 18 decimals using Chainlink price feeds.
     * @param _token Token address (address(0) for ETH).
     * @param _amount Amount of token in native units.
     * @return valueUSD Equivalent USD value with 18 decimals.
     * @dev Requires that a Chainlink feed is configured for `_token`. Reverts otherwise.
     */
    function _toUsd18(address _token, uint256 _amount) internal view returns (uint256 valueUSD) {
        AggregatorV3Interface priceFeed;
        uint8 tokenDecimals = 18;

        if (_token == address(0)) {
            priceFeed = i_ethPriceFeed;
        } else {
            priceFeed = s_tokenPriceFeeds[_token];
            if (address(priceFeed) == address(0))
                revert PriceFeedNotSet(_token);
        }

        uint256 price = _getLatestPrice(priceFeed);

        // Normalize amount to 18 decimals: amount * 10^(18 - tokenDecimals)
        uint256 normalizedAmount;
        if (tokenDecimals <= 18) {
            normalizedAmount = _amount * (10 ** (18 - tokenDecimals));
        } else {
            normalizedAmount = _amount / (10 ** (tokenDecimals - 18));
        }

        // valueUSD = normalizedAmount * price / (10^CHAINLINK_PRICE_DECIMALS)
        valueUSD = (normalizedAmount * price) / (10 ** CHAINLINK_PRICE_DECIMALS);
    }

    /**
     * @notice Get latest price from Chainlink feed, revert if invalid (!>0).
     * @param _feed AggregatorV3Interface feed to query.
     * @return price Price value as uint256 (feed decimals, usually 8).
     */
    function _getLatestPrice(AggregatorV3Interface _feed) internal view returns (uint256 price) {
        (, int256 answer, , , ) = _feed.latestRoundData();
        if (answer <= 0) revert PriceFeedInvalid();
        return uint256(answer);
    }

    /**
     * @notice Validate that the bank's USD cap is not exceeded by a new deposit.
     * @param _amountUSD Amount (in USD with 18 decimals) to validate.
     * @dev Reverts with DepositCapExceeded if cap would be exceeded.
     */
    function _validateCapUSD(uint256 _amountUSD) internal view {
        uint256 total = s_totalDepositedUSD;
        uint256 cap = s_bankCapUSD;
        if (total + _amountUSD > cap) revert DepositCapExceeded(_amountUSD, cap - total);
    }

    /*////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////*/

    /**
     * @notice Returns a user's token balance (native token units).
     * @param _user User address.
     * @param _token Token address (address(0) for ETH).
     * @return balance User's balance in token native units.
     */
    function getBalance(address _user, address _token) external view returns (uint256 balance) {
        return s_balances[_user][_token];
    }

    /**
     * @notice Returns the registered price feed address for a token (address(0) -> ETH feed).
     * @param _token Token address.
     * @return feedAddress Registered feed address.
     */
    function getTokenPriceFeed(address _token) external view returns (address feedAddress) {
        if (_token == address(0)) return address(i_ethPriceFeed);
        return address(s_tokenPriceFeeds[_token]);
    }

    /**
     * @notice Estimate a token amount in USD (18 decimals).
     * @param _token Token address (address(0) for ETH).
     * @param _amount Amount of token in native units.
     * @return usdValue Estimated USD value (18 decimals).
     */
    function estimateUsdValue(address _token, uint256 _amount) external view returns (uint256 usdValue) {
        return _toUsd18(_token, _amount);
    }

    /*////////////////////////////////////////////////////////////
                            FALLBACKS / RECEIVE
    ////////////////////////////////////////////////////////////*/

    /**
     * @notice Accept direct ETH deposits and treat them as a deposit.
     * @dev Behaves like deposit(address(0), msg.value) but optimized for receive gas costs.
     */
    receive() external payable {
        uint256 valueUSD = _toUsd18(address(0), msg.value);
        _validateCapUSD(valueUSD);
        s_balances[msg.sender][address(0)] += msg.value;
        s_totalDepositedUSD += valueUSD;
        ++s_totalDepositsCount;
        emit Deposit(msg.sender, address(0), msg.value, valueUSD);
    }

    /**
     * @notice Fallback to accept ETH transfers (with data) as deposits.
     */
    fallback() external payable {
        uint256 valueUSD = _toUsd18(address(0), msg.value);
        _validateCapUSD(valueUSD);
        s_balances[msg.sender][address(0)] += msg.value;
        s_totalDepositedUSD += valueUSD;
        ++s_totalDepositsCount;
        emit Deposit(msg.sender, address(0), msg.value, valueUSD);
    }
}

