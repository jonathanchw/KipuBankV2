# KipuBankV2

KipuBankV2 is an evolution of the original *KipuBank* contract, designed to simulate a basic banking infrastructure within the Ethereum ecosystem, incorporating best practices for security, scalability, and maintainability. This version introduces access control, multi-asset support, price queries via Chainlink, and mechanisms to mitigate common vulnerabilities.

---

## 1. Objectives and Improvements

The primary goal of this version is to strengthen the design of the original contract, addressing detected limitations and applying functionalities covered during the course. The improvements can be categorized as follows:

### **1.1. Access Control**
OpenZeppelin's `AccessControl` is implemented to manage permissions and restrict administrative functions to a specific role. This ensures the principle of **least privilege**, preventing arbitrary configurations by unauthorized users.

### **1.2. Multi-Token Support**
The contract is no longer limited to Ether and allows operation with multiple ERC-20 assets. To achieve this, the following are implemented:
- Nested mappings (`mapping(address => mapping(address => uint256))`)
- User- and token-specific balance tracking
- Use of `address(0)` to represent ETH as the system’s native asset

### **1.3. Oracles and Global Limit**
**Chainlink Data Feeds** are integrated to value deposited assets in USD and enforce a **global bank cap**. This feature improves accounting consistency and allows reasoning in a common unit of value.

### **1.4. Security**
Mechanisms are applied to mitigate known attack vectors:
- `ReentrancyGuard` to protect withdrawal functions
- **Checks → Effects → Interactions** pattern
- Custom errors to reduce gas costs and facilitate debugging

### **1.5. Events and Observability**
All critical operations emit events, improving on-chain traceability and integration with external applications or explorers such as Etherscan.

---

## 2. Deployment Instructions (Remix)

### **2.1. Prerequisites**
- Web browser
- **MetaMask** extension
- Testnet funds (e.g., Sepolia)
- Access to [https://remix.ethereum.org](https://remix.ethereum.org)

### **2.2. Steps**
1. Open Remix and create the `/contracts` folder
2. Copy `KipuBankV2.sol` into this folder
3. Install OpenZeppelin imports via **Remix Libraries** or direct import from the official repository
4. Select compiler `0.8.x` and compile
5. Open the **Deploy & Run** tab
6. Network: `Injected Provider – MetaMask`
7. Deploy the contract, assigning the `admin` role to `msg.sender`
8. Save the resulting address for future interactions

---

## 3. Interaction Instructions

Once deployed, typical actions include:

| Function | Description |
|---------|------------|
| `deposit()` | Allows sending ETH and crediting it to the internal balance |
| `depositToken(token, amount)` | Deposits a previously approved ERC-20 asset |
| `withdraw(amount)` | Withdraws ETH from the bank |
| `withdrawToken(token, amount)` | Withdraws an ERC-20 asset |
| `setPriceFeed(token, aggregator)` | Admin-only: registers a Chainlink oracle |
| `getUserBalance(user, token)` | Queries balances |
| `getTotalValueInUSD()` | Returns the total bank value in USD |

---

## 4. Design Decisions and Trade-offs

### **4.1. AccessControl vs Ownable**
`AccessControl` is chosen for its greater flexibility. It allows future scalability (multiple roles) without refactoring.

### **4.2. Reentrancy Prevention**
`ReentrancyGuard` is used even when applying CEI. It serves as an additional defense against human errors or future code changes.

### **4.3. Tokens Without Oracle**
For security reasons, the contract reverts when attempting to operate with assets not supported by a price feed. Accounting integrity is prioritized over flexibility.

### **4.4. `address(0)` for ETH**
This convention avoids duplicate logic and unifies accounting with ERC-20 tokens.

---

## 5. Deployment Status

| Network | Status | Address |
|-------|---------|-----------|
| Sepolia | *Deployed and pending verification* | 0xD31Ec1457Fa571EEcfB723905b2a780E0f30E4db |

---

## 6. License

MIT — free to use with attribution.


