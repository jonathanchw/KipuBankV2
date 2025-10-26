// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

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
